#include "p2phttpsrv.h"
#include "p2pmgmt.h"
#include "btype.h"
#include "app_log.h"

static void p2phttpcli_close(p2phttpcli_t *httpcli)
{
	p2phttpsrv_t *httpsrv = httpcli->httpsrv;
	p2pmgmt_t *mgmt = httpsrv->p2pmgmt;
	p2psched_t *stoping = httpsrv->stoping;
	p2psched_t *sched = httpcli->playts.p2psched;

	log_debug("httpcli close: %p", httpcli);
	DLIST_DEL(lhcli, httpcli->httpsrv->ltcli, httpcli);
	bufferevent_free(httpcli->bev);
	if (httpcli->type == HTTPCLI_PLAYTS) {
		event_del(&httpcli->playts.evtimer);
		if (sched != NULL) {
			if (stoping != NULL && stoping != sched)
				p2pmgmt_delsched(mgmt, stoping->cid);
			httpsrv->stoping = sched;
			p2psched_stop(sched);
		}
	}
	kfree(httpcli);
}

static void p2phttpcli_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	p2phttpcli_t *httpcli = user_data;
	p2phttpsrv_t *httpsrv = httpcli->httpsrv;

	if (events & BEV_EVENT_EOF) {
		log_info("Connection closed.\n");
	}
	else if (events & BEV_EVENT_ERROR) {
		log_info("Got an error on the connection: %s\n", strerror(errno));/*XXX win32*/
	}
	/* None of the other events can happen here, since we haven't enabled
	* timeouts */
	p2phttpcli_close(httpcli);
}

static int p2phttpcli_playts(p2phttpcli_t *httpcli);

static void p2phttpcli_writecb(struct bufferevent *bev, void *user_data)
{
	p2phttpcli_t *httpcli = (p2phttpcli_t *)user_data;

	if (httpcli->type == HTTPCLI_PLAYTS) {
		p2phttpcli_playts(httpcli);
	}
	else {
		struct evbuffer *output = bufferevent_get_output(bev);
		if (evbuffer_get_length(output) == 0)
			bufferevent_disable(bev, EV_WRITE);
	}
}

static void p2phttpcli_timer(evutil_socket_t fd, short event, void *arg)
{
	p2phttpcli_t *httpcli = (p2phttpcli_t *)arg;
	if (httpcli->type == HTTPCLI_PLAYTS) {
		p2phttpcli_playts(httpcli);
	}
}

static int p2phttpcli_playts(p2phttpcli_t *httpcli)
{
	p2phttpsrv_t *httpsrv = httpcli->httpsrv;
	p2pmgmt_t *mgmt = httpsrv->p2pmgmt;
	p2psched_t *sched = httpcli->playts.p2psched;
	p2pmsg_pack_t pack;
	int ipack = -1;
	uint32_t cid = strtoul(httpcli->buf + 14, NULL, 10);
	struct timeval tv = { 0, 5 * 1000 };
	char resphead[MAX_HEAD] = "HTTP/1.1 200 OK\r\nContent-Type: video/mp2ts\r\nCache-Control: no-cache\r\n\r\n";
	
	httpcli->type = HTTPCLI_PLAYTS;
	if (sched == NULL || sched->cid != cid) {
		if (sched != NULL)
			p2pmgmt_delsched(mgmt, sched->cid);

		sched = httpsrv->stoping;
		httpsrv->stoping = NULL;
		if (sched != NULL && sched->cid == cid)
			p2psched_start(sched);
		else {
			if (sched != NULL) 
				p2pmgmt_delsched(mgmt, sched->cid);
			sched = p2pmgmt_getsched(mgmt, cid, 0);
		}
		httpcli->playts.p2psched = sched;
		event_assign(&httpcli->playts.evtimer, httpsrv->evbase, -1, 0, p2phttpcli_timer, httpcli);
		bufferevent_enable(httpcli->bev, EV_WRITE);
		bufferevent_write(httpcli->bev, resphead, strlen(resphead));
	}

	if (httpcli->playts.packid == 0 || p2pcache_outdated(&sched->cache, httpcli->playts.packid))
		httpcli->playts.packid = p2pcache_findkeypack(&sched->cache);
	if (httpcli->playts.packid != 0)
		ipack = p2pcache_read(&sched->cache, httpcli->playts.packid, &pack);
	if (ipack < 0) {
		bufferevent_disable(httpcli->bev, EV_WRITE);
		event_add(&httpcli->playts.evtimer, &tv);
		return 0;
	}

	httpcli->playts.packid++;
	bufferevent_enable(httpcli->bev, EV_WRITE);
	event_del(&httpcli->playts.evtimer);
	bufferevent_write(httpcli->bev, pack.data, pack.len);
	p2pcache_freebuffer(pack.data);
	//log_debug("http write pack id:%llu key:%d len:%d", pack.packid, pack.attr, pack.len);
	return pack.len;
}

static void p2phttpcli_readcb(struct bufferevent *bev, void *user_data)
{
	p2phttpcli_t *httpcli = user_data;
	p2phttpsrv_t *httpsrv = httpcli->httpsrv;
	int len;
	char *p;

	len = bufferevent_read(bev, httpcli->buf + httpcli->len,
					sizeof(httpcli->buf) - httpcli->len - 1);
	if (len <= 0) return;
	httpcli->len += len;
	httpcli->buf[httpcli->len] = '\0';
	p = strstr(httpcli->buf, "\r\n\r\n");
	if (p == NULL)
		return;

	if (!strncasecmp(httpcli->buf, "GET /live?cid=", 14)) {
		p2phttpcli_playts(httpcli);
	}
}

static void p2phttpsrv_listencb(struct evconnlistener *listener, 
		evutil_socket_t fd, struct sockaddr *sa, int socklen, void *user_data)
{
	p2phttpsrv_t *httpsrv = user_data;
	struct bufferevent *bev;

	bev = bufferevent_socket_new(httpsrv->evbase, fd, BEV_OPT_CLOSE_ON_FREE);
	if (bev == NULL) {
		log_error("Error constructing bufferevent %s:%d!", 
				inet_ntoa(((struct sockaddr_in *)sa)->sin_addr), 
				ntohs(((struct sockaddr_in *)sa)->sin_port));
		return;
	}
	p2phttpcli_t *httpcli = kcalloc(1, sizeof(p2phttpcli_t));
	httpcli->httpsrv = httpsrv;
	httpcli->bev = bev;
	httpcli->len = 0;
	DLIST_ADD(lhcli, httpsrv->ltcli, httpcli);
	bufferevent_setcb(bev, p2phttpcli_readcb, p2phttpcli_writecb, p2phttpcli_eventcb, httpcli);
	bufferevent_enable(bev, EV_READ);
	bufferevent_disable(bev, EV_WRITE);
	log_debug("httpcli create: %p", httpcli);
	return;
}

static void p2phttpsrv_loop(void *param)
{
	p2phttpsrv_t *httpsrv = (p2phttpsrv_t *)param;
	p2phttpcli_t *httpcli, *nextcli;

	log_debug("httpsrv listening on %s:%u\n", httpsrv->ip, httpsrv->port);
	event_base_dispatch(httpsrv->evbase);
	log_debug("httpsrv destroy on %s:%u\n", httpsrv->ip, httpsrv->port);

	p2pmgmt_unref(httpsrv->p2pmgmt);
	evconnlistener_free(httpsrv->evlistener);
	event_base_free(httpsrv->evbase);
	DLIST_FOREACH(lhcli, httpsrv->ltcli, httpcli, nextcli) {
		p2phttpcli_close(httpcli);
	}
	kfree(httpsrv);
}

p2phttpsrv_t *p2phttpsrv_new(void *p2pmgmt, const char *ip, uint16_t port)
{
	p2phttpsrv_t *httpsrv = (p2phttpsrv_t *)kalloc(sizeof(p2phttpsrv_t));
	struct sockaddr_in addr;

	p2pmgmt_ref(p2pmgmt);
	httpsrv->p2pmgmt = p2pmgmt;
	httpsrv->stoping = NULL;
	strxcpy(httpsrv->ip, sizeof(httpsrv->ip), ip, -1);
	httpsrv->port = port;
	httpsrv->evbase = event_base_new();
	DLIST_INIT(httpsrv->ltcli);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(httpsrv->ip);
	addr.sin_port = htons(httpsrv->port);
	httpsrv->evlistener = evconnlistener_new_bind(httpsrv->evbase,
							p2phttpsrv_listencb, httpsrv,
							LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, 
							-1, (struct sockaddr*)&addr, sizeof(addr));
	if (httpsrv->evlistener != NULL) {
		if (0 == pthread_create(&httpsrv->tid, 0, p2phttpsrv_loop, httpsrv))
			return httpsrv;
	}

	log_error("Could not create a listener %s:%d!\n", ip, port);
	p2pmgmt_unref(p2pmgmt);
	event_base_free(httpsrv->evbase);
	kfree(httpsrv);
	return NULL;
}

void p2phttpsrv_destroy(p2phttpsrv_t *httpsrv)
{
	event_base_loopbreak(httpsrv->evbase);
}
