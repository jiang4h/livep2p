#include "p2phttpsrv.h"
#include "p2pmgmt.h"
#include "btype.h"
#include "app_log.h"

static void p2phttpcli_close(p2phttpcli_t *httpcli)
{
	p2phttpsrv_t *httpsrv = httpcli->httpsrv;

	log_debug("httpcli close: %p", httpcli);
	DLIST_DEL(lhcli, httpcli->httpsrv->ltcli, httpcli);
	event_del(&httpcli->evtimer);
	bufferevent_free(httpcli->bev);
	httpcli->bev = NULL;
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

static int p2phttpcli_playseg(p2phttpcli_t *httpcli, int newreq);
static int p2phttpcli_playm3u8(p2phttpcli_t *httpcli, int newreq);
static int p2phttpcli_playts(p2phttpcli_t *httpcli, int newreq);

static int p2phttpcli_nextreq(p2phttpcli_t *httpcli, struct bufferevent *bev)
{
	char *p = strstr(httpcli->buf + 13, "\r\n\r\n");
	if (p == NULL)
		httpcli->len = 0;
	else {
		p += 4;
		if (httpcli->len <= p - httpcli->buf)
			httpcli->len = 0;
		else {
			httpcli->len -= p - httpcli->buf;
			memmove(httpcli->buf, p, httpcli->len);
		}
	}
	httpcli->buf[httpcli->len] = '\0';
	if (httpcli->len <= 0) {
		bufferevent_disable(bev ? bev : httpcli->bev, EV_WRITE);
		return 0;
	}
	if (!strncasecmp(httpcli->buf, "GET /m3u8?cid=", 14))
		return p2phttpcli_playm3u8(httpcli, 1);
	else if (!strncasecmp(httpcli->buf, "GET /seg?cid=", 13))
		return p2phttpcli_playseg(httpcli, 1);
	else if (!strncasecmp(httpcli->buf, "GET /live?cid=", 14))
		return p2phttpcli_playts(httpcli, 1);
	return 0;
}

static void p2phttpcli_writecb(struct bufferevent *bev, void *user_data)
{
	p2phttpcli_t *httpcli = (p2phttpcli_t *)user_data;

	if (httpcli->type == HTTPCLI_PLAYTS) {
		p2phttpcli_playts(httpcli, 0);
	}
	else {
		if (httpcli->type == HTTPCLI_PLAYSEG) {
			if (p2phttpcli_playseg(httpcli, 0) > 0)
				return;
		}

		struct evbuffer *output = bufferevent_get_output(bev);
		if (evbuffer_get_length(output) == 0)
			p2phttpcli_nextreq(httpcli, bev);
	}
}

static void p2phttpcli_timer(evutil_socket_t fd, short event, void *arg)
{
	p2phttpcli_t *httpcli = (p2phttpcli_t *)arg;
	if (httpcli->type == HTTPCLI_PLAYTS) {
		p2phttpcli_playts(httpcli, 0);
	}
	else if (httpcli->type == HTTPCLI_PLAYM3U8) {
		p2phttpcli_playm3u8(httpcli, 0);
	}
}

static p2psched_t *p2phttpcli_sched(p2phttpcli_t *httpcli, uint32_t cid)
{
	p2phttpsrv_t *httpsrv = httpcli->httpsrv;
	p2pmgmt_t *mgmt = httpsrv->p2pmgmt;
	p2psched_t *sched = httpcli->p2psched;
	p2phttpcli_t *oldcli, *nextcli;

	if (sched != NULL && sched->cid == cid)
		return sched;

	if (sched != NULL && p2pmgmt_delsched(mgmt, sched->cid)) {
		if (sched == httpsrv->p2psched)
			httpsrv->p2psched = NULL;
		DLIST_FOREACH(lhcli, httpsrv->ltcli, oldcli, nextcli) {
			if (oldcli->p2psched == sched)
				p2phttpcli_close(oldcli);
		}
	}

	sched = httpsrv->p2psched;
	if (sched != NULL && sched->cid == cid) {
		httpcli->p2psched = sched;
		return sched;
	}

	if (sched != NULL && p2pmgmt_delsched(mgmt, sched->cid)) {
		DLIST_FOREACH(lhcli, httpsrv->ltcli, oldcli, nextcli) {
			if (oldcli->p2psched == sched)
				p2phttpcli_close(oldcli);
		}
	}

	sched = p2pmgmt_getsched(mgmt, cid, NULL, 0);
	httpcli->p2psched = sched;
	httpsrv->p2psched = sched;
	return sched;
}

static int p2phttpcli_playseg(p2phttpcli_t *httpcli, int newreq)
{
	p2psched_t *sched;
	uint32_t cid = strtoul(httpcli->buf + 13, NULL, 10);
	uint64_t firstpackid = 0, lastpackid = 0;
	p2pmsg_pack_t pack;
	int size = 0, ipack = -1;
	char resphead[1024], *p;

	httpcli->type = HTTPCLI_PLAYSEG;
	event_del(&httpcli->evtimer);

	p = strstr(httpcli->buf + 13, "&b=");
	if (p != NULL)
		firstpackid = strtoull(p + 3, NULL, 10);
	p = strstr(httpcli->buf + 13, "&e=");
	if (p != NULL)
		lastpackid = strtoull(p + 3, NULL, 10);
	p = strstr(httpcli->buf + 13, "&n=");
	if (p != NULL)
		size = strtoul(p + 3, NULL, 10);
	if (firstpackid == 0 || lastpackid == 0 || size <= 0) {
		if (!newreq)
			p2phttpcli_close(httpcli);
		else {
			bufferevent_enable(httpcli->bev, EV_WRITE);
			bufferevent_write(httpcli->bev,
				"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
				sizeof("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") - 1);
		}
		return 0;
	}

	sched = p2phttpcli_sched(httpcli, cid);
	if (newreq)
		httpcli->packid = firstpackid;
	else if (httpcli->packid > lastpackid) {
		log_debug("%d %llu ---%d", newreq, httpcli->packid, httpcli->sent);
		return p2phttpcli_nextreq(httpcli, NULL);
	}

	ipack = p2pcache_read(&sched->cache, httpcli->packid, &pack);
	//log_debug("%d %llu %d:%d", newreq, httpcli->packid, ipack, pack.len);
	if (ipack < 0) {
		if (!newreq)
			p2phttpcli_close(httpcli);
		else {
			bufferevent_enable(httpcli->bev, EV_WRITE);
			bufferevent_write(httpcli->bev,
				"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
				sizeof("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n") - 1);
		}
		return 0;
	}

	if (newreq) {
		snprintf(resphead, sizeof(resphead),
			"HTTP/1.1 200 OK\r\nContent-Type: video/mp2ts\r\n"
			"Cache-Control: no-cache\r\nContent-Length: %d\r\n\r\n", size);
		bufferevent_enable(httpcli->bev, EV_WRITE);
		bufferevent_write(httpcli->bev, resphead, strlen(resphead));
		httpcli->sent = 0;
		log_debug("%d %llu %s ---%d", newreq, httpcli->packid, httpcli->buf, size);
	}
	httpcli->sent += pack.len;
	do { httpcli->packid++; } while (httpcli->packid == 0);
	bufferevent_enable(httpcli->bev, EV_WRITE);
	bufferevent_write(httpcli->bev, pack.data, pack.len);
	p2pcache_freebuffer(pack.data);
	//log_debug("http write pack id:%llu key:%d len:%d", pack.packid, pack.attr, pack.len);
	return pack.len;
}

static int p2phttpcli_playm3u8(p2phttpcli_t *httpcli, int newreq)
{
	p2psched_t *sched;
	uint32_t cid = strtoul(httpcli->buf + 14, NULL, 10);
	char auth[40] = { 0 }, *p;
	char resphead[1024], *m3u8;
	int len = 0;
	struct timeval tv = { 0, 15 * 1000 };

	p = strstr(httpcli->buf + 14, "&auth=");
	if (p != NULL)
		memcpy(auth, p + 6, 32);

	httpcli->type = HTTPCLI_PLAYM3U8;
	sched = p2phttpcli_sched(httpcli, cid);
	m3u8 = p2pm3u8_text(&sched->m3u8, &len, auth);
	if (!m3u8)
		event_add(&httpcli->evtimer, &tv);
	else {
		event_del(&httpcli->evtimer);
		snprintf(resphead, sizeof(resphead),
			"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n"
			"Cache-Control: no-cache\r\nContent-Length: %d\r\n\r\n", len);
		bufferevent_enable(httpcli->bev, EV_WRITE);
		bufferevent_write(httpcli->bev, resphead, strlen(resphead));
		bufferevent_write(httpcli->bev, m3u8, len);
		log_debug("%d %d:%s", newreq, len, m3u8);
		kfree(m3u8);
	}
	return 0;
}

static int p2phttpcli_playts(p2phttpcli_t *httpcli, int newreq)
{
	p2psched_t *sched;
	p2pmsg_pack_t pack;
	int ipack = -1;
	uint32_t cid = strtoul(httpcli->buf + 14, NULL, 10);
	struct timeval tv = { 0, 5 * 1000 };

	httpcli->type = HTTPCLI_PLAYTS;
	sched = p2phttpcli_sched(httpcli, cid);

	if (newreq) {
		bufferevent_enable(httpcli->bev, EV_WRITE);
		bufferevent_write(httpcli->bev,
			"HTTP/1.1 200 OK\r\nContent-Type: video/mp2ts\r\nCache-Control: no-cache\r\n\r\n",
			sizeof("HTTP/1.1 200 OK\r\nContent-Type: video/mp2ts\r\nCache-Control: no-cache\r\n\r\n") - 1);
	}

	if (httpcli->packid == 0 || p2pcache_outdated(&sched->cache, httpcli->packid))
		httpcli->packid = p2pcache_findkeypack(&sched->cache);
	if (httpcli->packid != 0)
		ipack = p2pcache_read(&sched->cache, httpcli->packid, &pack);
	if (ipack < 0) {
		bufferevent_disable(httpcli->bev, EV_WRITE);
		event_add(&httpcli->evtimer, &tv);
		return 0;
	}

	do { httpcli->packid++; } while (httpcli->packid == 0);
	bufferevent_enable(httpcli->bev, EV_WRITE);
	event_del(&httpcli->evtimer);
	bufferevent_write(httpcli->bev, pack.data, pack.len);
	p2pcache_freebuffer(pack.data);
	//log_debug("http write pack id:%llu key:%d len:%d", pack.packid, pack.attr, pack.len);
	return pack.len;
}

static void p2phttpcli_readcb(struct bufferevent *bev, void *user_data)
{
	p2phttpcli_t *httpcli = user_data;
	p2phttpsrv_t *httpsrv = httpcli->httpsrv;
	p2pmgmt_t *mgmt = httpsrv->p2pmgmt;
	int len;
	char *p;
	char auth[40];
	uint32_t cid = 0, authtime, curtime;

	len = bufferevent_read(bev, httpcli->buf + httpcli->len,
					sizeof(httpcli->buf) - httpcli->len - 1);
	if (len <= 0) return;
	if (httpcli->len > 0 && strstr(httpcli->buf, "\r\n\r\n")) {
		httpcli->len += len;
		httpcli->buf[httpcli->len] = '\0';
		return;
	}
	httpcli->len += len;
	httpcli->buf[httpcli->len] = '\0';
	p = strstr(httpcli->buf, "\r\n\r\n");
	if (p == NULL) {
		bufferevent_enable(httpcli->bev, EV_WRITE);
		bufferevent_write(httpcli->bev,
			"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
			sizeof("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") - 1);
		return;
	}

	p = strstr(httpcli->buf + 5, "?cid=");
	if (p != NULL)
		cid = strtoul(p + 5, NULL, 10);

	p = strstr(httpcli->buf + 14, "&auth=");
	if (p == NULL) {
		bufferevent_enable(httpcli->bev, EV_WRITE);
		bufferevent_write(httpcli->bev,
			"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
			sizeof("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n") - 1);
		return;
	}
	memcpy(auth, p + 6, 32);
	authtime = p2pmgmt_authverify(cid, auth, 32);
	if (authtime <= 0) {
		bufferevent_enable(httpcli->bev, EV_WRITE);
		bufferevent_write(httpcli->bev,
			"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
			sizeof("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n") - 1);
		return;
	}

	if (!strncasecmp(httpcli->buf, "GET /m3u8?cid=", 14))
		p2phttpcli_playm3u8(httpcli, 1);
	else if (!strncasecmp(httpcli->buf, "GET /seg?cid=", 13))
		p2phttpcli_playseg(httpcli, 1);
	else if (!strncasecmp(httpcli->buf, "GET /live?cid=", 14)) {
		if (mgmt->updatetime != 0) {
			curtime = (uint32_t)((getcurtime_us() / 1000000) & 0xFFFFFFFFull) + mgmt->trktimediff / 1000;
			if (curtime > authtime + 3600 || authtime > curtime + 3600) {
				bufferevent_enable(httpcli->bev, EV_WRITE);
				bufferevent_write(httpcli->bev,
					"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
					sizeof("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n") - 1);
				return;
			}
		}
		p2phttpcli_playts(httpcli, 1);
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
	DLIST_ADD(lhcli, httpsrv->ltcli, httpcli);
	event_assign(&httpcli->evtimer, httpsrv->evbase, -1, 0, p2phttpcli_timer, httpcli);
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
	DLIST_FOREACH(lhcli, httpsrv->ltcli, httpcli, nextcli) {
		p2phttpcli_close(httpcli);
	}
	event_base_free(httpsrv->evbase);
	kfree(httpsrv);
}

p2phttpsrv_t *p2phttpsrv_new(void *p2pmgmt, const char *ip, uint16_t port)
{
	p2phttpsrv_t *httpsrv = (p2phttpsrv_t *)kalloc(sizeof(p2phttpsrv_t));
	struct sockaddr_in addr;

	p2pmgmt_ref(p2pmgmt);
	httpsrv->p2pmgmt = p2pmgmt;
	httpsrv->p2psched = NULL;
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
