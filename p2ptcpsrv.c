#include "p2ptcpsrv.h"
#include "p2pmgmt.h"
#include "btype.h"
#include "app_log.h"

static void p2ptcpcli_close(p2ptcpcli_t *tcpcli)
{
	log_debug("tcpcli close: %p", tcpcli);
	p2ptcpsrv_t *tcpsrv = tcpcli->tcpsrv;
	bufferevent_free(tcpcli->bev);
	DLIST_DEL(lhcli, tcpsrv->ltcli, tcpcli);
	if (tcpcli->buf != NULL)
		rudpbuffer_free(tcpcli->buf);
	kfree(tcpcli);
}

static void p2ptcpcli_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	p2ptcpcli_t *tcpcli = user_data;
	p2ptcpsrv_t *tcpsrv = tcpcli->tcpsrv;

	if (events & BEV_EVENT_EOF) {
		log_info("Connection closed.\n");
	}
	else if (events & BEV_EVENT_ERROR) {
		log_info("Got an error on the connection: %s\n", strerror(errno));/*XXX win32*/
	}
	/* None of the other events can happen here, since we haven't enabled
	* timeouts */
	p2ptcpcli_close(tcpcli);
}

static void p2ptcpcli_writecb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *output = bufferevent_get_output(bev);
	if (evbuffer_get_length(output) == 0) {
		bufferevent_disable(bev, EV_WRITE);
	}
}

static void p2ptcpcli_readcb(struct bufferevent *bev, void *user_data)
{
	p2ptcpcli_t *tcpcli = user_data;
	p2ptcpsrv_t *tcpsrv = tcpcli->tcpsrv;
	p2psched_t *sched = tcpsrv->p2psched;
	int tsnum = sched->cache.packsize / TS_SIZE;
	char *buf;
	int len;
	p2pmsg_pack_t pack;

	if (tcpcli->buf == NULL) {
		p2pcache_allocbuffer(tcpcli->buf, sched->p2psock, NULL);
		if (tcpcli->buf == NULL)
			return;
	}
	len = bufferevent_read(bev, tcpcli->buf + tcpcli->len, 
		sched->cache.packsize - tcpcli->len);
	if (len > 0) tcpcli->len += len;
	if (tcpcli->len < tsnum * TS_SIZE) return;

	for (len = 0; len < tcpcli->len - TS_SIZE; len++) {
		if (ts_validate(tcpcli->buf + len) &&
			ts_validate(tcpcli->buf + len + TS_SIZE)) break;
	}
	if (len == tcpcli->len - TS_SIZE) {
		p2ptcpcli_close(tcpcli);
		return;
	}
	else if (len > 0) {
		tcpcli->len -= len;
		memmove(tcpcli->buf, tcpcli->buf + len, tcpcli->len);
	}
	if (tcpcli->len < tsnum * TS_SIZE) return;
	
	tcpsrv->recvtime = getcurtime_us();

	pack.cmd.type = P2P_CMD_ACK_PACK;
	pack.cmd.seq = 0;
	pack.cmd.cid = sched->cid;
	pack.uid = sched->peer.uid;
	do { pack.packid = tcpcli->packseq++; } while (pack.packid == 0);
	pack.attr = ts_is_keyframe(sched->psh, tcpcli->buf, tcpcli->len);
	pack.len = len = tsnum * TS_SIZE;
	pack.data = buf = tcpcli->buf;
	p2pcache_write(&sched->cache, &pack);

	tcpcli->len -= len;
	tcpcli->buf = NULL;
	if (tcpcli->len > 0) {
		p2pcache_allocbuffer(tcpcli->buf, sched->p2psock, NULL);
		memcpy(tcpcli->buf, buf + len, tcpcli->len);
	}
}

static void p2ptcpsrv_listencb(struct evconnlistener *listener, 
		evutil_socket_t fd, struct sockaddr *sa, int socklen, void *user_data)
{
	p2ptcpsrv_t *tcpsrv = user_data;
	p2psched_t *sched = tcpsrv->p2psched;
	struct bufferevent *bev;

	bev = bufferevent_socket_new(tcpsrv->evbase, fd, BEV_OPT_CLOSE_ON_FREE);
	if (bev == NULL) {
		log_error("Error constructing bufferevent %s:%d!", 
				inet_ntoa(((struct sockaddr_in *)sa)->sin_addr), 
				ntohs(((struct sockaddr_in *)sa)->sin_port));
		return;
	}

	p2ptcpcli_t *tcpcli = kcalloc(1, sizeof(p2ptcpcli_t));
	tcpcli->packseq = (sched->cache.maxpackid == 0) ? 
		(getcurtime_us() - 1696089600000000ull) : (sched->cache.maxpackid + 1);
	tcpcli->tcpsrv = tcpsrv;
	tcpcli->bev = bev;

	DLIST_ADD(lhcli, tcpsrv->ltcli, tcpcli);

	bufferevent_setwatermark(bev, EV_READ, TS_SIZE, 2 * 1024 * (TS_SIZE * 7));
	bufferevent_setcb(bev, p2ptcpcli_readcb, p2ptcpcli_writecb, p2ptcpcli_eventcb, tcpcli);
	bufferevent_enable(bev, EV_READ);
	bufferevent_disable(bev, EV_WRITE);
	log_debug("tcpcli create: %p", tcpcli);
	return;
}

static void p2ptcpsrv_loop(void *param)
{
	p2ptcpsrv_t *tcpsrv = (p2ptcpsrv_t *)param;
	p2ptcpcli_t *tcpcli, *nextcli;

	log_debug("tcpsrv listening on %s:%u\n", tcpsrv->ip, tcpsrv->port);
	event_base_dispatch(tcpsrv->evbase);
	log_debug("tcpsrv destroy on %s:%u\n", tcpsrv->ip, tcpsrv->port);

	DLIST_FOREACH(lhcli, tcpsrv->ltcli, tcpcli, nextcli) {
		p2ptcpcli_close(tcpcli);
	}
	p2psched_unref(tcpsrv->p2psched);
	evconnlistener_free(tcpsrv->evlistener);
	event_base_free(tcpsrv->evbase);
	kfree(tcpsrv);
}

p2ptcpsrv_t *p2ptcpsrv_new(void *p2psched, const char *ip, uint16_t port)
{
	p2ptcpsrv_t *tcpsrv = (p2ptcpsrv_t *)kalloc(sizeof(p2ptcpsrv_t));
	struct sockaddr_in addr;

	p2psched_ref(p2psched);
	tcpsrv->p2psched = p2psched;
	strxcpy(tcpsrv->ip, sizeof(tcpsrv->ip), (ip && ip[0]) ? ip : "127.0.0.1", -1);
	tcpsrv->port = port;
	tcpsrv->recvtime = 0;
	tcpsrv->evbase = event_base_new();
	DLIST_INIT(tcpsrv->ltcli);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(tcpsrv->ip);
	addr.sin_port = htons(tcpsrv->port);
	tcpsrv->evlistener = evconnlistener_new_bind(tcpsrv->evbase,
							p2ptcpsrv_listencb, tcpsrv, 
							LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, 
							-1, (struct sockaddr*)&addr, sizeof(addr));
	if (tcpsrv->evlistener != NULL) {
		if (0 == pthread_create(&tcpsrv->tid, 0, p2ptcpsrv_loop, tcpsrv))
			return tcpsrv;
	}

	log_error("Could not create a listener %s:%d!\n", ip, port);
	p2psched_unref(p2psched);
	event_base_free(tcpsrv->evbase);
	kfree(tcpsrv);
	return NULL;
}

void p2ptcpsrv_destroy(p2ptcpsrv_t *tcpsrv)
{
	event_base_loopbreak(tcpsrv->evbase);
}
