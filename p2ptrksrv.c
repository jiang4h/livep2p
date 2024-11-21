#include "p2ptrksrv.h"
#include "p2pmgmt.h"
#include "app_log.h"

static void trkchannel_addpeer(trkchannel_t *channel, trkpeer_t *peer)
{
	HASH_ADD(hhpeer, channel->htpeer, peer.uid, sizeof(peer->peer.uid), peer);
	if (peer->peer.uid <= MAX_SERVER_UID)
		DLIST_ADD(lhpeer, channel->ltserver, peer);  //peer is server node
	else
		DLIST_ADD(lhpeer, channel->ltpeer, peer);
}

static void trkchannel_delpeer(trkchannel_t *channel, trkpeer_t *peer)
{
	HASH_DELETE(hhpeer, channel->htpeer, peer);
	if (peer->peer.uid <= MAX_SERVER_UID)
		DLIST_DEL(lhpeer, channel->ltserver, peer);
	else
		DLIST_DEL(lhpeer, channel->ltpeer, peer);
}

static trkpeer_t *trkchannel_nextpeer(trkchannel_t *channel, trkpeer_t *peer)
{
	trkpeer_t *nextpeer = peer->lhpeer.next;
	if (nextpeer == NULL) {
		if (peer->peer.uid > MAX_SERVER_UID)
			nextpeer = channel->ltserver.next;
	}
	return nextpeer;
}

static int p2ptrksrv_notifycb(rudpsession_t *session, char *buffer, int len, int ntftype, void *data)
{
	p2ptrksrv_t *tracker = (p2ptrksrv_t *)data;
	if (ntftype == RUDP_NOTIFY_FAIL)
		log_debug("send fail! [%x] %p\n", session->mysessid, session);
	return 0;
}

static int p2ptrksrv_closecb(rudpsession_t *session, void *data)
{
	p2ptrksrv_t *tracker = (p2ptrksrv_t *)data;
	uint32_t cid = *(uint32_t *)session->data;
	uint64_t uid = *(uint64_t *)(session->data + 4);
	trkchannel_t *channel = NULL;
	trkpeer_t *peer = NULL;

	if (cid == 0 || uid == 0) return 0;

	pthread_mutex_lock(&tracker->ht_lck);
	HASH_FIND(hhchannel, tracker->htchannel, &cid, sizeof(cid), channel);
	if (channel != NULL)
		trkchannel_ref(channel);
	pthread_mutex_unlock(&tracker->ht_lck);

	if (channel == NULL) return 0;

	pthread_wrlock_lock(&channel->rwlck);
	HASH_FIND(hhpeer, channel->htpeer, &uid, sizeof(uid), peer);
	if (peer != NULL && peer->rudpsess == session) {
		trkchannel_delpeer(channel, peer);
		trkpeer_destroy(peer);
	}
	pthread_wrlock_unlock(&channel->rwlck);

	trkchannel_unref(channel);
	return 0;
}

static int p2ptrksrv_destroycb(rudpsocket_t *rudpsock)
{
	p2ptrksrv_t *tracker = (p2ptrksrv_t *)rudpsock->data;

	p2ptrksrv_unref(tracker);
	return 0;
}

static int p2ptrksrv_recvcb(rudpsession_t *session, char *buffer, int len, void *data)
{
	p2ptrksrv_t *tracker = (p2ptrksrv_t *)data;
	trkchannel_t *channel;
	trkpeer_t *peer, *nextpeer;
	uint8_t cmdtype = GET_CMD_TYPE(buffer);
	trkpeercfg_t *peercfg = NULL;

	switch (cmdtype) {
	case P2P_CMD_REQ_LOGIN: {
		p2pmsg_req_login_t req;
		uint64_t curtime;
		p2pmsg_ack_login_t ack;
		rudppeer_t *sesspeer = session->rudppeer;
		char ackbuffer[MAX_MTU], *ptr_peernum, *ptr;

		curtime = getcurtime_us();
		p2pmsg_req_login_decode(buffer, &req);

		HASH_FIND(hhpeercfg, tracker->htpeercfg, &req.peer.uid, sizeof(req.peer.uid), peercfg);
		req.peer.wanip = (peercfg != NULL) ? peercfg->wanip :
			((struct sockaddr_in *)&sesspeer->addr)->sin_addr.s_addr;
		req.peer.wanport = ntohs(((struct sockaddr_in *)&sesspeer->addr)->sin_port);

		channel = p2ptrksrv_getchannel(tracker, req.cmd.cid);
		peer = trkchannel_getpeer(channel, session, &req, time_us2sec(curtime));

		ack.cmd.type = P2P_CMD_ACK_LOGIN;
		ack.cmd.seq = req.cmd.seq;
		ack.cmd.cid = req.cmd.cid;
		ack.uid = peer->peer.uid;
		ack.logintime = peer->peer.logintime;
		ack.curtime = time_us2ms(curtime);
		ack.wanip = peer->peer.wanip;
		ack.wanport = peer->peer.wanport;
		memcpy(&ack.param, &tracker->param, sizeof(ack.param));
		ack.peernum = 0;
		ptr = p2pmsg_ack_login_encode(ackbuffer, &ack);
		ptr_peernum = ptr - 1;
		pthread_rdlock_lock(&channel->rwlck);
		for (ack.peernum = 0, nextpeer = trkchannel_nextpeer(channel, peer);
			nextpeer != NULL && ack.peernum < req.getpeernum && ack.peernum < MAX_GETPEERNUM;
			ack.peernum++, nextpeer = trkchannel_nextpeer(channel, nextpeer)) {
			ptr = p2pmsg_peer_encode(ptr, &nextpeer->peer); //TODO: source in middle/logintime
		}
		pthread_rdlock_unlock(&channel->rwlck);
		*ptr_peernum = ack.peernum;
		rudpsess_send(session, ackbuffer, ptr - ackbuffer, time_us2ms(curtime));

		log_debug("recv login req from %llu, cid:%d, found %d peers", req.peer.uid, req.cmd.cid, ack.peernum);

		trkpeer_unref(peer);
		trkchannel_unref(channel);
		break;
	}
	case P2P_CMD_REQ_HELLO: {
		rudppeer_t *sesspeer = session->rudppeer;
		p2pmsg_req_hello_t req;
		uint32_t curtime;

		p2pmsg_req_hello_decode(buffer, &req);

		log_debug("recv punching hole req from %llu, cid:%d, dst uid:%llu", req.peer.uid, req.cmd.cid, req.dstuid);

		if (req.dstuid == 0) break;

		pthread_mutex_lock(&tracker->ht_lck);
		HASH_FIND(hhchannel, tracker->htchannel, &req.cmd.cid, sizeof(req.cmd.cid), channel);
		if (channel != NULL)
			trkchannel_ref(channel);
		pthread_mutex_unlock(&tracker->ht_lck);

		if (channel == NULL) break;

		pthread_rdlock_lock(&channel->rwlck);
		HASH_FIND(hhpeer, channel->htpeer, &req.dstuid, sizeof(req.dstuid), peer);
		if (peer != NULL)
			trkpeer_ref(peer);
		pthread_rdlock_unlock(&channel->rwlck);

		if (peer == NULL) {
			trkchannel_unref(channel);
			break;
		}

		HASH_FIND(hhpeercfg, tracker->htpeercfg, &req.peer.uid, sizeof(req.peer.uid), peercfg);
		req.peer.wanip = (peercfg != NULL) ? peercfg->wanip :
			((struct sockaddr_in *)&sesspeer->addr)->sin_addr.s_addr;
		req.peer.wanport = ntohs(((struct sockaddr_in *)&sesspeer->addr)->sin_port);

		p2pmsg_req_hello_encode(buffer, &req);

		curtime = getcurtime_ms();
		rudpsess_send(peer->rudpsess, buffer, len, curtime);

		trkpeer_unref(peer);
		trkchannel_unref(channel);
		break;
	}
	default:
		log_debug("unknown message");
		break;
	}

	rudpbuffer_free(buffer);
	return 0;
}

int trkpeer_ref(trkpeer_t *peer)
{
	return _sync_add32(&peer->refcnt, 1);
}

int trkpeer_unref(trkpeer_t *peer)
{
	int refcnt = _sync_add32(&peer->refcnt, -1);
	if (refcnt == 1) {
		log_debug("trkpeer freed:%p", peer);
		trkchannel_unref(peer->channel);
		kfree(peer);
	}
	return refcnt;
}

trkpeer_t *trkpeer_new(trkchannel_t *channel, rudpsession_t *session, p2pmsg_peer_t *msg)
{
	trkpeer_t *peer = kcalloc(1, sizeof(trkpeer_t));

	peer->refcnt = 1;
	memcpy(&peer->peer, msg, sizeof(p2pmsg_peer_t));
	while (peer->peer.uid == 0)
		peer->peer.uid = _sync_add64(&channel->tracker->uidseq, 1);
	peer->channel = channel;

	rudpsess_ref(session);
	*(uint32_t *)session->data = channel->cid;
	*(uint64_t *)(session->data + 4) = peer->peer.uid;
	peer->rudpsess = session;

	trkchannel_ref(channel);
	return peer;
}

void trkpeer_destroy(trkpeer_t *peer)
{
	rudpsession_t *session = peer->rudpsess;
	if (session != NULL) {
		peer->rudpsess = NULL;
		*(uint32_t *)session->data = 0;
		*(uint64_t *)(session->data + 4) = 0;
		rudpsess_close(session, 1);
	}
	trkpeer_unref(peer);
}

int trkchannel_ref(trkchannel_t *channel)
{
	return _sync_add32(&channel->refcnt, 1);
}

int trkchannel_unref(trkchannel_t *channel)
{
	int refcnt = _sync_add32(&channel->refcnt, -1);
	if (refcnt != 1)
		return refcnt;

	log_debug("trkchannel freed:%p", channel);
	p2ptrksrv_unref(channel->tracker);
	pthread_rwlock_destroy(&channel->rwlck);
	kfree(channel);
	return refcnt;
}

trkchannel_t *trkchannel_new(p2ptrksrv_t *tracker, uint32_t cid)
{
	trkchannel_t *channel = kcalloc(1, sizeof(trkchannel_t));
	channel->refcnt = 1;
	DLIST_INIT(channel->ltpeer);
	DLIST_INIT(channel->ltserver);
	pthread_rwlock_init(&channel->rwlck, 0);
	channel->cid = cid;
	channel->tracker = tracker;
	p2ptrksrv_ref(tracker);
	return channel;
}

trkpeer_t *trkchannel_getpeer(trkchannel_t *channel, rudpsession_t *session, p2pmsg_req_login_t *req, uint32_t curtime)
{
	trkpeer_t *peer = NULL;
	rudpsession_t *oldsess = NULL;

	pthread_wrlock_lock(&channel->rwlck);
	if (req->peer.uid != 0) {
		HASH_FIND(hhpeer, channel->htpeer, &req->peer.uid, sizeof(req->peer.uid), peer);
	}
	if (peer == NULL) {
		peer = trkpeer_new(channel, session, &req->peer);
		trkchannel_addpeer(channel, peer);
	}
	else if (peer->rudpsess != session) {
		oldsess = peer->rudpsess;
		rudpsess_ref(session);
		*(uint32_t *)session->data = channel->cid;
		*(uint64_t *)(session->data + 4) = req->peer.uid;
		peer->rudpsess = session;
		memcpy(&peer->peer, &req->peer, sizeof(p2pmsg_peer_t));
	}
	peer->peer.logintime = curtime;
	peer->upperuid = req->upperuid;
	peer->upperrate = req->upperrate;
	peer->startpackid = req->startpackid;
	peer->maxpackid = req->maxpackid;
	if (req->push != 0 && peer->peer.uid <= MAX_SERVER_UID) {
		DLIST_MOVE_TAIL(lhpeer, channel->ltserver, peer);
	}
	trkpeer_ref(peer);
	pthread_wrlock_unlock(&channel->rwlck);

	if (oldsess != NULL) 
		rudpsess_close(oldsess, 1);
	return peer;
}

void trkchannel_destroy(trkchannel_t *channel)
{
	trkpeer_t *peer, *nextpeer;

	pthread_wrlock_lock(&channel->rwlck);
	HASH_ITER(hhpeer, channel->htpeer, peer, nextpeer) {
		trkchannel_delpeer(channel, peer);
		trkpeer_destroy(peer);
	}
	pthread_wrlock_unlock(&channel->rwlck);
	trkchannel_unref(channel);
}

int p2ptrksrv_ref(p2ptrksrv_t *tracker)
{
	return _sync_add32(&tracker->refcnt, 1);
}

int p2ptrksrv_unref(p2ptrksrv_t *tracker)
{
	int refcnt = _sync_add32(&tracker->refcnt, -1);
	if (refcnt != 1)
		return refcnt;

	log_debug("p2ptrksrv freed:%p", tracker);
	pthread_mutex_destroy(&tracker->ht_lck);
	if (tracker->wp->owner == tracker) rudpworker_destroy(tracker->wp);
	kfree(tracker);

	return refcnt;
}

void mgtif_req_html(SOCKET sockfd, char *req, const char *curdir)
{
	char resp[MAX_HEAD];
	char *p;
	char urlpath[MAX_BASEPATH] = { 0 };
	FILE *fp;
	int len, i;
	static int mime_num = 9;
	static char *mime_type[18] = { ".html", "text/html",
	  ".css", "text/css", ".js", "application/x-javascript",
	  ".htm", "text/html", ".png", "image/png",
	  ".jpg", "image/jpeg", ".jpeg", "image/jpeg",
	  ".gif", "image/gif", ".pdf", "application/pdf" };

	p = strchr(req + strlen("GET /"), '?');
	if (p != NULL)
		*p = '\0';
	p = req + strlen("GET /");
	snprintf(urlpath, sizeof(urlpath), "%s%s", curdir, p);
#ifdef _WIN32
	char filepath[MAX_BASEPATH];
	p = _fullpath(filepath, urlpath, sizeof(filepath));
#else
	char filepath[PATH_MAX];
	p = realpath(urlpath, filepath);
#endif
	if (p == NULL) { // html/file.html
		snprintf(resp, sizeof(resp),
			"HTTP/1.1 403 Permission Denied\r\nConnection: close\r\n\r\nfile <%s> is invalid.", p);
		send(sockfd, resp, strlen(resp), 0);
		return;
	}
	if (!strstr(filepath, curdir)) {
		snprintf(resp, sizeof(resp),
			"HTTP/1.1 403 Permission Denied\r\nConnection: close\r\n\r\nfile <%s> not in dir <%s>.",
			filepath, curdir);
		send(sockfd, resp, strlen(resp), 0);
		return;
	}
	fp = fopen(filepath, "r");
	if (fp == NULL) {
		snprintf(resp, sizeof(resp),
			"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nfile <%s> not found.", filepath);
		send(sockfd, resp, strlen(resp), 0);
		return;
	}

	strcpy(resp, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
	p = strrchr(filepath, '.');
	if (p != NULL) {
		for (i = 0; i < mime_num; i++) {
			if (strcasecmp(p, mime_type[i * 2]) == 0) {
				snprintf(resp, sizeof(resp),
					"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nConnection: close\r\n\r\n",
					mime_type[i * 2 + 1]);
				break;
			}
		}
	}
	len = strlen(resp);
	if (send(sockfd, resp, len, 0) < len) {
		fclose(fp);
		return;
	}
	while (1) {
		len = fread(resp, 1, sizeof(resp), fp);
		if (len > 0) {
			if (send(sockfd, resp, len, 0) < len)
				break;
		}
		if (len < sizeof(resp))
			break;
	}
	fclose(fp);
}

#define url_nextpara(_para,_name,_value) \
	_name = _para; \
	_value = strchr(_name, '&'); \
	if (_value == NULL) \
		_para = _name + strlen(_name); \
	else { \
		*_value = '\0'; \
		_para = _value + 1; \
	} \
	_value = strchr(_name, '='); \
	if (_value == NULL) \
		_value = _name + strlen(_name); \
	else { \
		*_value = '\0'; \
		_value = _value + 1; \
	}

static void mgtif_req_peerinfo(SOCKET sockfd, char *req, int para, p2ptrksrv_t *tracker)
{
	char url[MAX_URL];
	char *p, *p1, *p2, callback[32] = { 0 };
	char resp_json[MAX_HEAD];
	struct in_addr addr;
	uint32_t cid = 0;
	trkchannel_t *channel, *nextch;
	trkpeer_t *peer, *nextpeer;
	char lanip[16], wanip[16];
	int num = 0;

	p = req + para;
	if (*p == '?') {
		p++;
		p1 = strchr(p, ' ');
		strxcpy(url, sizeof(url), p, (p1 == NULL) ? -1 : (p1 - p));
		p = url;
		while (p[0] != '\0') {
			url_nextpara(p, p1, p2);
			if (!strcmp(p1, "cid"))
				cid = strtoull(p2, NULL, 10);
			else if (!strcmp(p1, "callback"))
				strxcpy(callback, sizeof(callback), p2, -1);
		}
	}

	snprintf(resp_json, sizeof(resp_json),
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n%s%s[", callback, (callback[0] != '\0') ? "(" : "");
	send(sockfd, resp_json, strlen(resp_json), 0);

	pthread_mutex_lock(&tracker->ht_lck);
	HASH_ITER(hhchannel, tracker->htchannel, channel, nextch) {
		if (cid == 0 || channel->cid == cid) {
			pthread_rdlock_lock(&channel->rwlck);
			HASH_ITER(hhpeer, channel->htpeer, peer, nextpeer) {
				addr.s_addr = peer->peer.lanip;
				inet_ntop(AF_INET, &addr, lanip, sizeof(lanip));
				addr.s_addr = peer->peer.wanip;
				inet_ntop(AF_INET, &addr, wanip, sizeof(wanip));
				snprintf(resp_json, sizeof(resp_json),
					"%s{\"cid\":%u,\"uid\":%llu,\"lanip\":\"%s\",\"lanport\":%d,\"wanip\":\"%s\",\"wanport\":%d,\"logintime\":%u,\"buildtime\":%u,\"upperuid\":%llu,\"upperrate\":%u,\"startpackid\":%llu,\"maxpackid\":%llu}",
					(num++ > 0) ? "," : "", channel->cid, peer->peer.uid, lanip, peer->peer.lanport, wanip, peer->peer.wanport, peer->peer.logintime, peer->peer.buildtime, peer->upperuid, peer->upperrate, peer->startpackid, peer->maxpackid);
				send(sockfd, resp_json, strlen(resp_json), 0);
			}
			pthread_rdlock_unlock(&channel->rwlck);
		}
	}
	pthread_mutex_unlock(&tracker->ht_lck);

	snprintf(resp_json, sizeof(resp_json), "]%s", (callback[0] != '\0') ? ")" : "");
	send(sockfd, resp_json, strlen(resp_json), 0);
}

static void mgtif_req_authcode(SOCKET sockfd, char *req, int para, p2ptrksrv_t *tracker)
{
	char url[MAX_URL];
	char *p, *p1, *p2, callback[32] = { 0 };
	char resp_json[MAX_HEAD];
	uint32_t cid = 0;
	trkchannel_t *channel, *nextch;
	uint32_t curtime;
	char auth[40];
	int num = 0;

	p = req + para;
	if (*p == '?') {
		p++;
		p1 = strchr(p, ' ');
		strxcpy(url, sizeof(url), p, (p1 == NULL) ? -1 : (p1 - p));
		p = url;
		while (p[0] != '\0') {
			url_nextpara(p, p1, p2);
			if (!strcmp(p1, "cid"))
				cid = strtoull(p2, NULL, 10);
			else if (!strcmp(p1, "callback"))
				strxcpy(callback, sizeof(callback), p2, -1);
		}
	}

	snprintf(resp_json, sizeof(resp_json),
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n%s%s[", callback, (callback[0] != '\0') ? "(" : "");
	send(sockfd, resp_json, strlen(resp_json), 0);

	curtime = (uint32_t)((getcurtime_us() / 1000000) & 0xFFFFFFFFull);
	if (cid == 0) {
		pthread_mutex_lock(&tracker->ht_lck);
		HASH_ITER(hhchannel, tracker->htchannel, channel, nextch) {
			if (cid == 0 || channel->cid == cid) {
				p2pmgmt_authcreate(channel->cid, auth, sizeof(auth), curtime);
				snprintf(resp_json, sizeof(resp_json), "%s{\"cid\":%u,\"auth\":\"%s\"}", (num++ > 0) ? "," : "", channel->cid, auth);
				send(sockfd, resp_json, strlen(resp_json), 0);
			}
		}
		pthread_mutex_unlock(&tracker->ht_lck);
	}
	else {
		p2pmgmt_authcreate(cid, auth, sizeof(auth), curtime);
		snprintf(resp_json, sizeof(resp_json), "%s{\"cid\":%u,\"auth\":\"%s\"}", (num++ > 0) ? "," : "", cid, auth);
		send(sockfd, resp_json, strlen(resp_json), 0);
	}

	snprintf(resp_json, sizeof(resp_json), "]%s", (callback[0] != '\0') ? ")" : "");
	send(sockfd, resp_json, strlen(resp_json), 0);
}

pthread_fn mgtif_loop(void *param)
{
	p2ptrksrv_t *tracker = (p2ptrksrv_t *)param;
	char curdir[MAX_BASEPATH];
	int one = 1, status, err;
	struct sockaddr_in sinaddr;
	SOCKET sockfds[FD_SETSIZE];
	uint32_t exptime[FD_SETSIZE];
	char *buffer[FD_SETSIZE];
	int buflen[FD_SETSIZE];
	char host[64], rd_resp[256];
	fd_set *rset;
	struct timeval tv;
	int fdmax, recvlen;
	int socknum = sizeof(sockfds) / sizeof(sockfds[0]), i;
	char *p, *p1;
	uint32_t curtime;

	getcurpath(curdir, sizeof(curdir));

	log_info("mgtif begin %d [%s]\n", tracker->rudpsock->port, curdir);
	for (i = 0; i < socknum; i++)
		sockfds[i] = INVALID_SOCKET;

	tracker->ifsock = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	setsockopt(tracker->ifsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_port = htons(tracker->rudpsock->port);
	sinaddr.sin_addr.s_addr = INADDR_ANY;
	status = bind(tracker->ifsock, (struct sockaddr *)&sinaddr, sizeof(sinaddr));
	if (status < 0) {
		err = sockerr;
		log_info("mgtif bind %d error %d:%s\n", tracker->rudpsock->port, err, strsockerr(err));
		closesocket(tracker->ifsock);
		tracker->ifsock = INVALID_SOCKET;
		p2ptrksrv_unref(tracker);
		return 0;
	}

#ifdef NFDBITS
	int rsmax = FD_SETSIZE / NFDBITS;
	int rsnum = tracker->ifsock / NFDBITS;
	if (rsnum >= rsmax)
		rsmax = rsnum + 1;
	rset = kalloc(rsmax * (NFDBITS / 8));
#else
	rset = kalloc(sizeof(fd_set));
#endif

	status = listen(tracker->ifsock, 3);
	while (!tracker->exiting) {
#ifdef NFDBITS
		memset(rset, 0, rsmax * (NFDBITS / 8));
#else
		FD_ZERO(rset);
#endif
		FD_SET(tracker->ifsock, rset);
		fdmax = tracker->ifsock;
		for (i = 0; i < socknum; i++) {
			if (sockfds[i] != INVALID_SOCKET)
				FD_SET(sockfds[i], rset);
			if (fdmax < sockfds[i])
				fdmax = sockfds[i];
		}
		fdmax++;

		curtime = getcurtime_ms();
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		status = select(fdmax, rset, NULL, NULL, &tv);
		if (status == 0) {
			for (i = 0; i < socknum; i++) {
				if (sockfds[i] != INVALID_SOCKET && curtime > exptime[i]) {
					shutdown(sockfds[i], 2);
					closesocket(sockfds[i]);
					sockfds[i] = INVALID_SOCKET;
					kfree(buffer[i]);
				}
			}
			continue;
		}

		for (i = 0; i < socknum; i++) {
			if (sockfds[i] == INVALID_SOCKET)
				continue;
			if (!FD_ISSET(sockfds[i], rset)) {
				if (curtime > exptime[i]) {
					shutdown(sockfds[i], 2);
					closesocket(sockfds[i]);
					sockfds[i] = INVALID_SOCKET;
					kfree(buffer[i]);
				}
				continue;
			}

			exptime[i] = curtime + 15 * 1000;
			recvlen = recv(sockfds[i], buffer[i] + buflen[i], MAX_HEAD - 1 - buflen[i], 0);
			if (recvlen <= 0) {
				if (recvlen == 0 || !SOCK_ERR_EAGAIN) {
					shutdown(sockfds[i], 2);
					closesocket(sockfds[i]);
					sockfds[i] = INVALID_SOCKET;
					kfree(buffer[i]);
				}
				continue;
			}
			buflen[i] += recvlen;
			buffer[i][buflen[i]] = '\0';
			if (strstr(buffer[i], "\r\n\r\n") == NULL)
				continue;

			host[0] = '\0';
			p = strstr(buffer[i], "\r\nHost: ");
			if (p != NULL) {
				p = p + 8;
				p1 = strstr(p, "\r\n");
				if (p1 != NULL)
					strxcpy(host, sizeof(host), p, p1 - p);
			}

			p = strchr(buffer[i] + 5, ' ');
			if (p != NULL)
				*p = '\0';
			log_info("url:%s\n", buffer[i]);

			if (!strcmp(buffer[i], "GET /")) {
				snprintf(rd_resp, sizeof(rd_resp), "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/html/index.html\r\nConnection: close\r\n\r\n", host);
				send(sockfds[i], rd_resp, strlen(rd_resp), 0);
			}
			else if (!strncmp(buffer[i], "GET /html/", 10))
				mgtif_req_html(sockfds[i], buffer[i], curdir);
			else if (!strncmp(buffer[i], "GET /json/peerinfo", 18))
				mgtif_req_peerinfo(sockfds[i], buffer[i], 18, tracker);
			else if (!strncmp(buffer[i], "GET /json/authcode", 18))
				mgtif_req_authcode(sockfds[i], buffer[i], 18, tracker);

			shutdown(sockfds[i], 2);
			closesocket(sockfds[i]);
			sockfds[i] = INVALID_SOCKET;
			kfree(buffer[i]);
		}

		if (tracker->ifsock != INVALID_SOCKET && FD_ISSET(tracker->ifsock, rset)) {
			int sinlen = sizeof(sinaddr);
			SOCKET sockfd = accept(tracker->ifsock, (struct sockaddr *)&sinaddr, &sinlen);
			if (sockfd == INVALID_SOCKET) {
				break; //shutdown tracker->ifsock
			}

			for (i = 0; i < socknum; i++) {
				if (sockfds[i] == INVALID_SOCKET) {
					sockfds[i] = sockfd;
					exptime[i] = curtime + 15 * 1000;
					buffer[i] = kalloc(MAX_HEAD);
					buflen[i] = 0;
					break;
				}
			}
			if (i >= socknum) //rejected
				closesocket(sockfd);
#ifdef NFDBITS
			else {
				int rsnum = sockfd / NFDBITS;
				if (rsnum >= rsmax) {
					rsmax = rsnum + 1;
					rset = krealloc(rset, rsmax * (NFDBITS / 8));
				}
			}
#endif
		}
	}

	shutdown(tracker->ifsock, 2);
	closesocket(tracker->ifsock);
	tracker->ifsock = INVALID_SOCKET;
	kfree(rset);
	p2ptrksrv_unref(tracker);
	return 0;
}

p2ptrksrv_t *p2ptrksrv_new(const char *cfgfile)
{
	cJSON *p2pcfg, *ci, *ci2, *ci3;
	int threadnum = 4;
	char ip[16] = "0.0.0.0";
	uint16_t port = 0;
	p2ptrksrv_t *tracker;

	p2pcfg = p2pmgmt_loadcfg(cfgfile);
	if (!p2pcfg) {
		log_error("load config fail: %s", cfgfile);
		return NULL;
	}
	
	if (ci = cJSON_GetObjectItem(p2pcfg, "threadnum")) {
		threadnum = ci->valueint;
	}
	if (ci = cJSON_GetObjectItem(p2pcfg, "trksrv")) {
		if (ci2 = cJSON_GetObjectItem(ci, "ip"))
			strxcpy(ip, sizeof(ip), ci2->valuestring, -1);
		if (ci2 = cJSON_GetObjectItem(ci, "port")) {
			port = ci2->valueint;
		}
	}

	if (port <= 0) {
		cJSON_Delete(p2pcfg);
		return NULL;
	}

	tracker = kcalloc(1, sizeof(p2ptrksrv_t));
	tracker->refcnt = 3;
	tracker->uidseq = getcurtime_us() - 1696252634000000;
	p2pmgmt_cfgparam(&tracker->param, p2pcfg);
	pthread_mutex_init(&tracker->ht_lck, 0);
	tracker->wp = rudpworker_new(threadnum, tracker);
	tracker->rudpsock = rudpsock_new(tracker->wp, ip, port, 12, tracker->param.trkinter * 3 / 1000,
		tracker->param.mtu - RUDP_OVERHEAD, tracker->param.interval, tracker->param.minrto,
		tracker->param.fastresend, tracker->param.wndsize, tracker->param.xmitmax, tracker->param.sndtimeout,
		RUDP_NOTIFY_FAIL, p2ptrksrv_recvcb, p2ptrksrv_notifycb, p2ptrksrv_closecb, p2ptrksrv_destroycb, tracker);

	if (ci = cJSON_GetObjectItem(p2pcfg, "peercfg")) {
		cJSON_ArrayForEach(ci2, ci) {
			uint64_t uid = 0;
			if (ci3 = cJSON_GetObjectItem(ci2, "uid"))
				uid = strtoull(ci3->valuestring, NULL, 10);
			if (ci3 = cJSON_GetObjectItem(ci2, "wanip")) {
				char *wanip = ci3->valuestring;
				if (uid != 0) {
					trkpeercfg_t *peercfg = kalloc(sizeof(trkpeercfg_t));
					peercfg->uid = uid;
					peercfg->wanip = inet_addr(wanip);
					HASH_ADD(hhpeercfg, tracker->htpeercfg, uid, sizeof(peercfg->uid), peercfg);
				}
			}
		}
	}

	cJSON_Delete(p2pcfg);

	if (tracker->rudpsock == NULL) {
		rudpworker_destroy(tracker->wp);
		kfree(tracker);
		return NULL;
	}

	tracker->ifsock = INVALID_SOCKET;
	if (pthread_create(&tracker->if_tid, NULL, mgtif_loop, (void *)tracker) != 0)
		p2ptrksrv_unref(tracker);

	return tracker;
}

trkchannel_t *p2ptrksrv_getchannel(p2ptrksrv_t *tracker, uint32_t cid)
{
	trkchannel_t *channel;

	pthread_mutex_lock(&tracker->ht_lck);
	HASH_FIND(hhchannel, tracker->htchannel, &cid, sizeof(cid), channel);
	if (channel == NULL) {
		channel = trkchannel_new(tracker, cid);
		HASH_ADD(hhchannel, tracker->htchannel, cid, sizeof(channel->cid), channel);
	}
	trkchannel_ref(channel);
	pthread_mutex_unlock(&tracker->ht_lck);
	return channel;
}

void p2ptrksrv_destroy(p2ptrksrv_t *tracker)
{
	trkchannel_t *channel, *nextch;
	trkpeercfg_t *peercfg, *nextcfg;

	if (tracker->exiting) return;
	tracker->exiting = 1;

	if (tracker->ifsock != INVALID_SOCKET)
		shutdown(tracker->ifsock, 2);

	pthread_mutex_lock(&tracker->ht_lck);
	HASH_ITER(hhchannel, tracker->htchannel, channel, nextch) {
		HASH_DELETE(hhchannel, tracker->htchannel, channel);
		trkchannel_destroy(channel);
	}
	pthread_mutex_unlock(&tracker->ht_lck);

	rudpsock_close(tracker->rudpsock);

	HASH_ITER(hhpeercfg, tracker->htpeercfg, peercfg, nextcfg) {
		HASH_DELETE(hhpeercfg, tracker->htpeercfg, peercfg);
		kfree(peercfg);
	}

	if (tracker->if_tid != 0)
		pthread_join(tracker->if_tid, NULL);
	p2ptrksrv_unref(tracker);
}