#include "p2psched.h"
#include "p2pmgmt.h"
#include "rudpsock.h"
#include "app_log.h"

#define STATUS_INIT     0
#define STATUS_RUNNING  1
#define STATUS_CLOSING -1

int p2psched_ref(p2psched_t *sched)
{
	return _sync_add32(&sched->refcnt, 1);
}

int p2psched_unref(p2psched_t *sched)
{
	int refcnt = _sync_add32(&sched->refcnt, -1);
	if (refcnt == 1) {
		log_debug("p2psched freed: %p", sched);
		pthread_mutex_destroy(&sched->ht_lck);
		p2pcache_destroy(&sched->cache);
		p2pm3u8_destroy(&sched->m3u8);
		ts_stream_close_handle(sched->psh);
		p2pmgmt_unref(sched->p2pmgmt);
		kfree(sched);
	}
	return refcnt;
}

#define p2psched_newreq(sched,_req,cmdtype) do { \
	uint8_t _seq = (uint8_t)(_sync_add32(&(sched)->reqseq, 1) & 0x000000FF); \
	(_req).cmd.type = cmdtype; \
	(_req).cmd.seq = _seq; \
	(_req).cmd.cid = sched->cid; \
} while (0)

#define p2psched_newack(_ack,_req) do { \
	(_ack).cmd.type = GET_CMD_ACKTYPE((_req)->cmd.type); \
	(_ack).cmd.seq  = (_req)->cmd.seq; \
	(_ack).cmd.cid  = (_req)->cmd.cid; \
} while (0)

#define p2psched_reqnum(sched)        ((sched)->reqseq)

static void p2psched_setpeersess(p2psched_t *sched, p2ppeer_t *peer, rudpsession_t *session)
{
	struct sockaddr_in *sa;

	if (session == NULL) return;

	if (peer->usesess == NULL) {
		if (peer->upper) {
			if (sched->reqtail == NULL)
				DLIST_MOVE(lhpeer, sched->ltupper, peer);
			else if (sched->reqtail != peer) {
				DLIST_DEL(lhpeer, sched->ltupper, peer);
				DLIST_INSERT(lhpeer, sched->ltupper, sched->reqtail, peer);
			}
			sched->reqtail = peer;
		}
		p2ppeer_setusesess(peer, session);
	}

	sa = &((rudppeer_t *)session->rudppeer)->addr;
	if (peer->peer.wanip == sa->sin_addr.s_addr)
		p2ppeer_setwansess(peer, session);
	else if (peer->peer.lanip == sa->sin_addr.s_addr)
		p2ppeer_setlansess(peer, session);
}

static p2ppeer_t *p2psched_getpeer(p2psched_t *sched, p2pmsg_peer_t *msg, int upper, rudpsession_t *session)
{
	p2ppeer_t *peer;

	pthread_mutex_lock(&sched->ht_lck);
	HASH_FIND(hhpeer, sched->htpeer, &msg->uid, sizeof(msg->uid), peer);
	if (peer != NULL) {
		if (peer->upper && !upper) {
			peer->waiting = 0; //reset peer to lower
			DLIST_DEL(lhpeer, sched->ltupper, peer);
			DLIST_ADD_TAIL(lhpeer, sched->ltlower, peer);
			peer->upper = upper;
		}
		else if (upper && !peer->upper) {
			if (upper != -1) { //-1: not change lower to upper
				peer->waiting = 0; //reset peer to upper
				DLIST_DEL(lhpeer, sched->ltlower, peer);
				DLIST_ADD_TAIL(lhpeer, sched->ltupper, peer);
				peer->upper = upper;
			}
		}
		memcpy(&peer->peer, msg, sizeof(peer->peer));
	}
	else {
		peer = p2ppeer_new(sched, msg, upper);
		HASH_ADD(hhpeer, sched->htpeer, peer.uid, sizeof(peer->peer.uid), peer);
		if (upper) DLIST_ADD_TAIL(lhpeer, sched->ltupper, peer);
		else DLIST_ADD_TAIL(lhpeer, sched->ltlower, peer);
	}

	p2psched_setpeersess(sched, peer, session); //re-sort
	p2ppeer_ref(peer);
	pthread_mutex_unlock(&sched->ht_lck);
	return peer;
}

static p2ppeer_t *p2psched_findpeer(p2psched_t *sched, uint64_t uid, rudpsession_t *session)
{
	p2ppeer_t *peer;

	pthread_mutex_lock(&sched->ht_lck);
	HASH_FIND(hhpeer, sched->htpeer, &uid, sizeof(uid), peer);
	if (peer == NULL) {
		pthread_mutex_unlock(&sched->ht_lck);
		return NULL;
	}
	p2psched_setpeersess(sched, peer, session);
	p2ppeer_ref(peer);
	pthread_mutex_unlock(&sched->ht_lck);
	return peer;
}

static int p2psched_droppeer(p2psched_t *sched, uint64_t uid, uint32_t curtime)
{
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	p2ppeer_t *peer;

	pthread_mutex_lock(&sched->ht_lck);
	if (sched->requid == uid)
		sched->requid = 0;
	HASH_FIND(hhpeer, sched->htpeer, &uid, sizeof(uid), peer);
	if (peer && peer->upper) {
		if (sched->reqtail != NULL && peer != sched->reqtail) {
			DLIST_DEL(lhpeer, sched->ltupper, peer);
			DLIST_INSERT(lhpeer, sched->ltupper, sched->reqtail, peer);
			sched->reqtail = peer;
		}
		peer->waiting = (curtime != 0 && curtime != -1) ? curtime : 1; //unusable from now on
	}
	peer = DLIST_HEAD(sched->ltupper);
	if (peer && (peer->waiting == 0 || peer->waiting == -1 ||
		(int32_t)(curtime - peer->waiting) > mgmt->param.blktimeout)) {
		pthread_mutex_unlock(&sched->ht_lck);
		return 1; //can change peer right now
	}
	pthread_mutex_unlock(&sched->ht_lck);
	return 0; //no valid peer
}

static void p2psched_delpeer(p2psched_t *sched, uint64_t uid, rudpsession_t *session)
{
	p2ppeer_t *peer;

	pthread_mutex_lock(&sched->ht_lck);
	HASH_FIND(hhpeer, sched->htpeer, &uid, sizeof(uid), peer);
	if (peer == NULL) {
		pthread_mutex_unlock(&sched->ht_lck);
		return;
	}
	if (session != NULL && peer->usesess != session) {
		pthread_mutex_unlock(&sched->ht_lck);
		p2ppeer_closesess(peer, session);
		return;
	}
	HASH_DELETE(hhpeer, sched->htpeer, peer);
	if (peer->upper) {
		if (sched->reqtail == peer)
			sched->reqtail = DLIST_PREV(lhpeer, peer);
		DLIST_DEL(lhpeer, sched->ltupper, peer);
	}
	else
		DLIST_DEL(lhpeer, sched->ltlower, peer);
	pthread_mutex_unlock(&sched->ht_lck);
	p2ppeer_destroy(peer);
}

static uint32_t p2psched_recvrate(p2psched_t *sched, uint64_t uid)
{
	p2ppeer_t *peer = NULL;
	uint32_t recvrate = 0;

	pthread_mutex_lock(&sched->ht_lck);
	HASH_FIND(hhpeer, sched->htpeer, &uid, sizeof(uid), peer);
	if (peer != NULL)
		recvrate = p2ppeer_recvrate(peer);
	pthread_mutex_unlock(&sched->ht_lck);
	return recvrate;
}

static int p2psched_lowernum(p2psched_t *sched)
{
	p2ppeer_t *peer, *peernext;
	int num = 0;

	pthread_mutex_lock(&sched->ht_lck);
	DLIST_FOREACH(lhpeer, sched->ltlower, peer, peernext) {
		num += p2ppeer_inuse(peer);
	}
	pthread_mutex_unlock(&sched->ht_lck);
	return num;
}

static void p2psched_settrksess(p2psched_t *sched, rudpsession_t *session)
{
	rudpsession_t *oldtrksess = NULL;

	pthread_mutex_lock(&sched->ht_lck);
	if (sched->trksess != session) {
		oldtrksess = sched->trksess;
		if (session != NULL)
			rudpsess_ref(session);
		sched->trksess = session;
	}
	pthread_mutex_unlock(&sched->ht_lck);
	if (oldtrksess != NULL) rudpsess_close(oldtrksess, 1);
}

static rudpsession_t *p2psched_gettrksess(p2psched_t *sched)
{
	rudpsession_t *trksess = NULL;

	pthread_mutex_lock(&sched->ht_lck);
	trksess = sched->trksess;
	if (trksess != NULL)
		rudpsess_ref(trksess);
	pthread_mutex_unlock(&sched->ht_lck);
	return trksess;
}

#define p2psched_log_msg(_cmd,_session,...) \
	log_debug(_cmd " session:%p %s:%d %s:%d", ##__VA_ARGS__, _session, \
		_session ? inet_ntoa(((struct sockaddr_in *)&((rudppeer_t *)_session->rudppeer)->addr)->sin_addr) : "none", \
		_session ? ntohs(((struct sockaddr_in *)&((rudppeer_t *)_session->rudppeer)->addr)->sin_port) : 0, \
		__FILE__, __LINE__);

#define p2psched_block_nodata(_pack_,_cmdtype_,_req_,_sched_,_packid_) do { \
	(_pack_).cmd.type = _cmdtype_; \
	(_pack_).cmd.seq = (_req_)->seq; \
	(_pack_).cmd.cid = (_sched_)->cid; \
	(_pack_).uid = (_sched_)->peer.uid; \
	(_pack_).packid = _packid_; \
	(_pack_).attr = 0; \
	(_pack_).len = 0; \
} while (0)

#define p2psched_block_ackdata(_pack_,_cmdtype_,_req_,_sched_) do { \
	(_pack_).cmd.type = _cmdtype_; \
	(_pack_).cmd.seq = (_req_)->seq; \
	(_pack_).cmd.cid = (_sched_)->cid; \
	(_pack_).uid = (_sched_)->peer.uid; \
} while (0)

static int p2psched_notifycb(rudpsession_t *session, char *buf, int len, int ntftype, void *data)
{
	p2psched_t *sched = (p2psched_t *)data;
	uint64_t uid = *(uint64_t *)session->data;

	if (uid == 0) return 0;

	if (ntftype == RUDP_NOTIFY_NEXT) {
		p2ppeer_t *peer = p2psched_findpeer(sched, uid, session);
		uint32_t curtime, waiting;
		p2pmgmt_t *mgmt;
		uint64_t packid;
		int i, ipack;
		p2pmsg_pack_t pack;
		char ackbuffer[MAX_MTU], *ptr = NULL;

		if (!peer || peer->upper)
			return 0;

		waiting = peer->waiting;
		if (peer->waiting == 0 || peer->waiting == -1) {
			p2ppeer_unref(peer);
			return 0;
		}
		
		curtime = getcurtime_ms();
		mgmt = sched->p2pmgmt;
		if ((int32_t)(curtime - peer->waiting) > (int32_t)mgmt->param.blktimeout ||
			peer->waitblk.bm.bitstart >= peer->waitblk.bm.bitsize) {
			peer->waiting = 0;
			p2ppeer_unref(peer);
			return 0;
		}

		for (i = peer->waitblk.bm.bitstart; i < peer->waitblk.bm.bitsize; i++) {
			packid = peer->waitblk.bm.startpackid + i;
			if (packid == 0 || p2pbitmap_get(&peer->waitblk.bm, i))
				continue;
			ipack = p2pcache_read(&sched->cache, packid, &pack); //TODO: req old data
			if (ipack < 0)  //no data
				break;

			if (rudpsess_cansend(session) <= 0) {
				p2psched_log_msg("buffer full to send pack %llu to %llu", session, packid, peer->peer.uid);
				break;
			}
			p2psched_block_ackdata(pack, P2P_CMD_ACK_PACK, &peer->waitreq, sched);
			ptr = p2pmsg_pack_encode(ackbuffer, &pack);
			p2pcache_freebuffer(pack.data);
			rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
		}

		if (peer->waiting == waiting) { //TODO: new blk req
			if (i >= peer->waitblk.bm.bitsize)
				peer->waiting = 0;
			else {
				peer->waitblk.bm.bitstart = i;
				if (ptr != NULL) //ack data
					peer->waiting = (curtime != 0 && curtime != -1) ? curtime : 1;
			}
		}
		p2ppeer_unref(peer);
	}
	return 0;
}

static int p2psched_closecb(rudpsession_t *session, void *data)
{
	p2psched_t *sched = (p2psched_t *)data;
	uint64_t uid = *(uint64_t *)session->data;

	if (sched->trksess == session) {
		pthread_mutex_lock(&sched->ht_lck);
		if (sched->trksess == session) {
			rudpsess_unref(sched->trksess);
			sched->trksess = NULL;
		}
		pthread_mutex_unlock(&sched->ht_lck);
	}

	if (uid == 0) return 0;

	p2psched_delpeer(sched, uid, session);
	return 0;
}

static int p2psched_destroycb(rudpsocket_t *rudpsock)
{
	p2psched_t *sched = (p2psched_t *)rudpsock->data;

	p2psched_unref(sched);
	return 0;
}

static void p2psched_login_req(p2psched_t *sched)
{
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	p2pmsg_req_login_t req;
	char reqbuffer[MAX_MTU], *ptr;
	uint64_t curtime = getcurtime_us();
	rudpsession_t *trksess;

	p2psched_newreq(sched, req, P2P_CMD_REQ_LOGIN);
	memcpy(&req.peer, &sched->peer, sizeof(req.peer));
	req.peer.buildtime = get_build_time(); //version
	req.upperuid = sched->requid;
	req.upperrate = p2psched_recvrate(sched, req.upperuid);
	req.startpackid = sched->cache.startpackid;
	req.maxpackid = sched->cache.maxpackid;
	req.push = (sched->tcpsrv != NULL && sched->tcpsrv->recvtime != 0 &&
		(int64_t)(curtime - sched->tcpsrv->recvtime) < 1000LL * mgmt->param.trkinter) ? 1 : 0;
	if (DLIST_COUNT(sched->ltupper) >= MAX_GETPEERNUM / 2)
		req.getpeernum = 0;
	else
		req.getpeernum = MAX_GETPEERNUM;
	ptr = p2pmsg_req_login_encode(reqbuffer, &req);

	trksess = p2psched_gettrksess(sched);
	if (trksess == NULL) {
		trksess = rudpsock_connect(sched->p2psock, inet_addr(mgmt->trkip), mgmt->trkport);
		if (trksess != NULL)
			p2psched_settrksess(sched, trksess);;
	}

	if (trksess != NULL) {
		rudpsess_send(trksess, reqbuffer, ptr - reqbuffer, time_us2ms(curtime));
		rudpsess_unref(trksess);
	}

	log_debug("login to trksrv %s:%d, cid:%d, session:%p, peernum:%d",
		mgmt->trkip, mgmt->trkport, sched->cid, trksess, req.getpeernum);
}

static void p2psched_hello_req(p2ppeer_t *peer)
{
	p2psched_t *sched = peer->p2psched;
	rudpsession_t *session;
	p2pmsg_req_hello_t req;
	char buf[MAX_MTU], *ptr;
	uint32_t curtime = getcurtime_ms();
	struct in_addr addr;
	char wanip[16];

	p2psched_newreq(sched, req, P2P_CMD_REQ_HELLO);
	memcpy(&req.peer, &sched->peer, sizeof(req.peer));
	req.dstuid = 0;
	ptr = p2pmsg_req_hello_encode(buf, &req);

	session = p2ppeer_getusesess(peer);
	if (session != NULL) {  //already connected
		rudpsess_send(session, buf, ptr - buf, curtime);
		p2psched_log_msg("say hello to %llu, cid:%d", session, peer->peer.uid, sched->cid);
		rudpsess_unref(session);
		return;
	}

	//say hello to the peer at the first time
	//peer has wan ip
	if (peer->peer.lanip == peer->peer.wanip) {
		session = p2ppeer_getwansess(peer);
		if (session == NULL) {
			session = rudpsock_connect(sched->p2psock, peer->peer.wanip, peer->peer.wanport);
			p2ppeer_setwansess(peer, session);
		}
		rudpsess_send(session, buf, ptr - buf, curtime);
		p2psched_log_msg("say hello to %llu, cid:%d", session, peer->peer.uid, sched->cid);
		rudpsess_unref(session);
		return;
	}

	//probably in same lan
	if (sched->peer.wanip == peer->peer.wanip) {
		session = p2ppeer_getlansess(peer);
		if (session == NULL) {
			session = rudpsock_connect(sched->p2psock, peer->peer.lanip, peer->peer.lanport);
			p2ppeer_setlansess(peer, session);
		}
		rudpsess_send(session, buf, ptr - buf, curtime);
		p2psched_log_msg("say hello to %llu, cid:%d", session, peer->peer.uid, sched->cid);
		rudpsess_unref(session);
	}

	session = p2ppeer_getwansess(peer);
	if (session == NULL) {
		session = rudpsock_connect(sched->p2psock, peer->peer.wanip, peer->peer.wanport);
		p2ppeer_setwansess(peer, session);
	}
	rudpsess_send(session, buf, ptr - buf, curtime);
	p2psched_log_msg("say hello to %llu, cid:%d", session, peer->peer.uid, sched->cid);
	rudpsess_unref(session);

	//punching hole at the same time, relay by tracker
	if (sched->trksess != NULL) {
		session = p2psched_gettrksess(sched);
		if (session != NULL) {
			req.dstuid = peer->peer.uid;
			ptr = p2pmsg_req_hello_encode(buf, &req);
			rudpsess_send(session, buf, ptr - buf, curtime);
			addr.s_addr = peer->peer.wanip;
			inet_ntop(AF_INET, &addr, wanip, sizeof(wanip));
			p2psched_log_msg("punching hole to %llu, cid:%d %s:%d",
				session, peer->peer.uid, sched->cid, wanip, peer->peer.wanport);
			rudpsess_unref(session);
		}
	}
}

static void p2psched_hello_ack(p2ppeer_t *peer, rudpsession_t *session, p2pmsg_req_hello_t *req)
{
	p2psched_t *sched = peer->p2psched;
	p2pmsg_ack_hello_t ack;
	char ackbuffer[MAX_MTU], *ptr;
	uint32_t curtime = getcurtime_ms();

	p2psched_newack(ack, req);
	memcpy(&ack.peer, &sched->peer, sizeof(ack.peer));
	ptr = p2pmsg_ack_hello_encode(ackbuffer, &ack);

	if (session != NULL) {
		rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
		p2psched_log_msg("ack hello to %llu, cid:%d", session, peer->peer.uid, sched->cid);
	}
	else {
		session = p2ppeer_getwansess(peer);
		if (session == NULL) {
			session = rudpsock_connect(sched->p2psock, peer->peer.wanip, peer->peer.wanport);
			p2ppeer_setwansess(peer, session);
		}
		rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
		p2psched_log_msg("ack hello to %llu, cid:%d", session, peer->peer.uid, sched->cid);
		rudpsess_unref(session);
	}
}

#define p2psched_block_req(sched) p2psched_block_req_dbg(sched, __FILE__, __LINE__)

static void p2psched_block_req_dbg(p2psched_t *sched, const char *file, int line)
{
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	p2ppeer_t *peer;
	rudpsession_t *session;
	uint32_t curtime = getcurtime_ms();
	char reqbuffer[MAX_MTU], *ptr;
	p2pblock_t *reqblk;
	struct timeval tv = { mgmt->param.blktimeout / 1000,
		mgmt->param.blktimeout % 1000 * 1000 };

	pthread_mutex_lock(&sched->ht_lck);
	peer = DLIST_HEAD(sched->ltupper);
	if (peer == NULL || peer->usesess == NULL) {
		sched->requid = 0;
		pthread_mutex_unlock(&sched->ht_lck);
		_sync_cas32(&sched->status, STATUS_RUNNING, STATUS_INIT);
		return;
	}
	if (sched->requid == peer->peer.uid &&
		peer->waiting != 0 && peer->waiting != -1 &&
		(int32_t)(curtime - peer->waiting) <= (int32_t)mgmt->param.blktimeout &&
		((sched->reqblk == NULL && peer->waitblk.bm.startpackid == 0) ||
		 (sched->reqblk != NULL && peer->waitblk.bm.startpackid == sched->reqblk->bm.startpackid))) {
		pthread_mutex_unlock(&sched->ht_lck);
		return;
	}
	sched->requid = peer->peer.uid;
	peer->waiting = (curtime != 0 && curtime != -1) ? curtime : 1;
	peer->waitblk.bm.startpackid = (sched->reqblk == NULL) ? 0 : sched->reqblk->bm.startpackid;
	p2ppeer_ref(peer);
	pthread_mutex_unlock(&sched->ht_lck);

	reqblk = sched->reqblk;
	if (reqblk == NULL) {
		p2pmsg_req_block_any_t req;

		p2psched_newreq(sched, req, P2P_CMD_REQ_BLOCK_ANY);
		req.uid = sched->peer.uid;
		req.bitsize = sched->cache.blocksize;
		ptr = p2pmsg_req_block_any_encode(reqbuffer, &req);
	}
	else {
		p2pmsg_req_block_t req;

		p2psched_newreq(sched, req, P2P_CMD_REQ_BLOCK);
		req.uid = sched->peer.uid;
		memcpy(&req.bitmap, &reqblk->bm, sizeof(req.bitmap));
		ptr = p2pmsg_req_block_encode(reqbuffer, &req);
	}

	session = p2ppeer_getusesess(peer);
	if (session != NULL) {
		sched->reqtime = curtime;
		rudpsess_send(session, reqbuffer, ptr - reqbuffer, curtime);
		p2psched_log_msg("request block %llu from %llu, cid:%d/%p, %s:%d",
			session, reqblk ? reqblk->bm.startpackid : 0, peer->peer.uid, sched->cid, sched, file, line);
		rudpsess_unref(session);
	}
	p2ppeer_unref(peer);

	event_del(&sched->blktimer);
	if (sched->status != STATUS_CLOSING) {
		event_add(&sched->blktimer, &tv);
		if (sched->status == STATUS_CLOSING) event_del(&sched->blktimer);
	}
}

static void p2psched_block_any_ack(p2psched_t *sched, rudpsession_t *session, p2pmsg_req_block_any_t *req)
{
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	p2ppeer_t *peer;
	p2pmsg_pack_t pack;
	uint16_t cmdtype, i;
	uint64_t packid, startpackid;
	int ipack;
	char ackbuffer[MAX_MTU], *ptr;
	uint32_t curtime = getcurtime_ms();
	int num, maxlower;

	if (req->cmd.cid != sched->cid) return;
	if (req->uid == 0) return;

	peer = p2psched_findpeer(sched, req->uid, session);
	if (peer == NULL) return;

	p2ppeer_setusesess(peer, session);

	maxlower = (sched->peer.uid <= MAX_SERVER_UID) ? mgmt->param.maxlowers : mgmt->param.maxlowerc;
	if (maxlower && !p2ppeer_inuse(peer)) {
		num = p2psched_lowernum(sched);
		if (num >= maxlower) {
			p2psched_block_nodata(pack, P2P_CMD_ACK_PACK_ANY, &req->cmd, sched, 0);
			ptr = p2pmsg_pack_encode(ackbuffer, &pack);
			rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
			p2psched_log_msg("exceed max lowers %d/%d, reject %llu, cid:%d", session, num, maxlower, peer->peer.uid, sched->cid);
			p2ppeer_unref(peer);
			return;
		}
	}

	cmdtype = P2P_CMD_ACK_PACK_ANY;
	packid = p2pcache_findkeypack(&sched->cache);
	if (packid == 0) {  //no data
		p2psched_block_nodata(pack, cmdtype, &req->cmd, sched, 0);
		ptr = p2pmsg_pack_encode(ackbuffer, &pack);
		rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
		p2psched_log_msg("no data to %llu, cid:%d", session, peer->peer.uid, sched->cid);
		p2ppeer_unref(peer);
		return;
	}

	peer->waiting = -1; //TODO:one req per lower
	startpackid = p2pblock_startpackid(packid, req->bitsize);
	for (i = packid - startpackid; i < req->bitsize; i++) {
		packid = startpackid + i;
		if (packid == 0)
			continue;
		ipack = p2pcache_read(&sched->cache, packid, &pack);
		if (ipack < 0) {  //no data
			p2psched_block_nodata(pack, cmdtype, &req->cmd, sched, packid);
			ptr = p2pmsg_pack_encode(ackbuffer, &pack);
			rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
			p2psched_log_msg("no pack %llu to %llu, cid:%d", session, packid, peer->peer.uid, sched->cid);
			break;
		}

		if (rudpsess_cansend(session) <= 0) {
			p2psched_log_msg("buffer full to send pack %llu to %llu, cid:%d", session, packid, peer->peer.uid, sched->cid);
			break;
		}
		p2psched_block_ackdata(pack, cmdtype, &req->cmd, sched);
		ptr = p2pmsg_pack_encode(ackbuffer, &pack);
		p2pcache_freebuffer(pack.data);
		rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
		cmdtype = P2P_CMD_ACK_PACK;
	}
	if (i >= req->bitsize)
		peer->waiting = 0;
	else {
		memcpy(&peer->waitreq, &req->cmd, sizeof(req->cmd));
		p2pblock_init(&peer->waitblk, req->bitsize, startpackid + i);
		peer->waiting = (curtime != 0 && curtime != -1) ? curtime : 1;
	}
	p2ppeer_unref(peer);
}

static void p2psched_block_ack(p2psched_t *sched, rudpsession_t *session, p2pmsg_req_block_t *req)
{
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	p2ppeer_t *peer;
	p2pmsg_pack_t pack;
	uint64_t packid;
	uint16_t i;
	int ipack;
	char ackbuffer[MAX_MTU], *ptr;
	uint32_t curtime = getcurtime_ms();
	int num, maxlower;

	if (req->cmd.cid != sched->cid) return;
	if (req->uid == 0) return;

	peer = p2psched_findpeer(sched, req->uid, session);
	if (peer == NULL) return;

	p2ppeer_setusesess(peer, session);

	maxlower = (sched->peer.uid <= MAX_SERVER_UID) ? mgmt->param.maxlowers : mgmt->param.maxlowerc;
	if (maxlower && !p2ppeer_inuse(peer)) {
		num = p2psched_lowernum(sched);
		if (num >= maxlower) {
			p2psched_block_nodata(pack, P2P_CMD_ACK_PACK_ANY, &req->cmd, sched, 0);
			ptr = p2pmsg_pack_encode(ackbuffer, &pack);
			rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
			p2psched_log_msg("exceed max lowers %d/%d, reject %llu, cid:%d", session, num, maxlower, peer->peer.uid, sched->cid);
			p2ppeer_unref(peer);
			return;
		}
	}

	packid = req->bitmap.startpackid + req->bitmap.bitstart;
	if (p2pcache_outdated(&sched->cache, packid)) {
		p2psched_block_nodata(pack, P2P_CMD_ACK_PACK, &req->cmd, sched, 0);
		ptr = p2pmsg_pack_encode(ackbuffer, &pack);
		rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
		p2psched_log_msg("outdated pack %llu to %llu, cid:%d", session, packid, peer->peer.uid, sched->cid);
		p2ppeer_unref(peer);
		return;
	}

	peer->waiting = -1;
	for (i = req->bitmap.bitstart; i < req->bitmap.bitsize; i++) {
		packid = req->bitmap.startpackid + i;
		if (packid == 0 || p2pbitmap_get(&req->bitmap, i))
			continue;
		ipack = p2pcache_read(&sched->cache, packid, &pack); //TODO: req old data
		if (ipack < 0) {  //no data
			p2psched_block_nodata(pack, P2P_CMD_ACK_PACK, &req->cmd, sched, packid);
			ptr = p2pmsg_pack_encode(ackbuffer, &pack);
			rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
			p2psched_log_msg("no pack %llu to %llu, cid:%d", session, packid, peer->peer.uid, sched->cid);
			break;
		}

		if (rudpsess_cansend(session) <= 0) {
			p2psched_log_msg("buffer full to send pack %llu to %llu, cid:%d", session, packid, peer->peer.uid, sched->cid);
			break;
		}
		p2psched_block_ackdata(pack, P2P_CMD_ACK_PACK, &req->cmd, sched);
		ptr = p2pmsg_pack_encode(ackbuffer, &pack);
		p2pcache_freebuffer(pack.data);
		rudpsess_send(session, ackbuffer, ptr - ackbuffer, curtime);
	}
	if (i >= req->bitmap.bitsize)
		peer->waiting = 0;
	else {
		memcpy(&peer->waitreq, &req->cmd, sizeof(req->cmd));
		p2pblock_setbm(&peer->waitblk, &req->bitmap, i);
		peer->waiting = (curtime != 0 && curtime != -1) ? curtime : 1;
	}
	p2ppeer_unref(peer);
}

static int p2psched_recvcb(rudpsession_t *session, char *buffer, int len, void *data)
{
	p2psched_t *sched = (p2psched_t *)data;
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	uint8_t cmdtype = GET_CMD_TYPE(buffer);

	switch (cmdtype) {
	case P2P_CMD_ACK_LOGIN: {
		p2pmsg_ack_login_t ack;
		int i;
		p2ppeer_t *peer;
		struct timeval tv = { mgmt->param.hlotimeout / 1000,
			mgmt->param.hlotimeout % 1000 * 1000 };
		uint32_t curtime;

		p2pmsg_ack_login_decode(buffer, &ack);
		if (ack.cmd.cid != sched->cid) break;

		sched->peer.logintime = ack.logintime;
		sched->peer.uid = ack.uid;
		sched->peer.wanip = ack.wanip;
		sched->peer.wanport = ack.wanport;
		
		curtime = getcurtime_ms();
		mgmt->trktimediff = ack.curtime - curtime;
		memcpy(&mgmt->param, &ack.param, sizeof(mgmt->param));
		mgmt->updatetime = curtime;

		p2psched_log_msg("recv login ack with %d peers, cid:%d", session, ack.peernum, sched->cid);

		for (i = 0; i < ack.peernum; i++) {
			peer = p2psched_getpeer(sched, &ack.peers[i], 1, NULL);
			if (peer->usesess == NULL)
				p2psched_hello_req(peer);
			p2ppeer_unref(peer);
		}

		p2pmgmt_setuid(mgmt, ack.uid);

		if (sched->status != STATUS_CLOSING) {
			event_add(&sched->hlotimer, &tv);
			if (sched->status == STATUS_CLOSING) event_del(&sched->hlotimer);
		}
		break;
	}
	case P2P_CMD_REQ_HELLO: {
		p2pmsg_req_hello_t req;
		p2ppeer_t *peer;
		rudpsession_t *peersess;

		p2pmsg_req_hello_decode(buffer, &req);
		if (req.cmd.cid != sched->cid) break;

		p2psched_log_msg("recv hello req from %llu, cid:%d", session, req.peer.uid, sched->cid);

		peersess = (req.dstuid == 0) ? session : NULL;
		peer = p2psched_getpeer(sched, &req.peer, 0, peersess);
		if (peer->usesess == peersess)
			p2psched_hello_ack(peer, peersess, &req);
		p2ppeer_unref(peer);
		break;
	}
	case P2P_CMD_ACK_HELLO: {
		p2pmsg_ack_hello_t ack;
		p2ppeer_t *peer;
		int status;

		p2pmsg_ack_hello_decode(buffer, &ack);
		if (ack.cmd.cid != sched->cid) break;

		p2psched_log_msg("recv hello ack from %llu, cid:%d", session, ack.peer.uid, sched->cid);

		peer = p2psched_getpeer(sched, &ack.peer, -1, session);
		if (peer->upper) {
			status = _sync_cas32(&sched->status, STATUS_INIT, STATUS_RUNNING);
			if (status == STATUS_INIT)
				p2psched_block_req(sched);
		}
		p2ppeer_unref(peer);
		break;
	}
	case P2P_CMD_REQ_BLOCK_ANY: {
		p2pmsg_req_block_any_t req;

		p2pmsg_req_block_any_decode(buffer, &req);
		p2psched_block_any_ack(sched, session, &req);
		break;
	}
	case P2P_CMD_REQ_BLOCK: {
		p2pmsg_req_block_t req;

		p2pmsg_req_block_decode(buffer, &req);
		p2psched_block_ack(sched, session, &req);
		break;
	}
	case P2P_CMD_ACK_PACK_ANY:
	case P2P_CMD_ACK_PACK: {
		p2pmsg_ack_pack_t pack;
		p2pblock_t *reqblk;
		uint32_t curtime;

		p2pmsg_pack_decode(buffer, &pack);
		if (pack.cmd.cid != sched->cid)
			break;

		curtime = getcurtime_ms();
		if (cmdtype == P2P_CMD_ACK_PACK_ANY && pack.packid == 0) { //no data
			if (p2psched_droppeer(sched, pack.uid, curtime)) //change peer
				p2psched_block_req(sched);
			break;
		}

		sched->rsptime = curtime;

		if (cmdtype == P2P_CMD_ACK_PACK && pack.packid == 0) { //packid outdated
			sched->reqblk = NULL;
			p2psched_block_req(sched);
			break;
		}

		if (pack.len == 0)
			break;

		reqblk = sched->reqblk;
		if (reqblk != NULL && !p2pblock_contains(reqblk, pack.packid))
			break;

		reqblk = p2pcache_write(&sched->cache, &pack); //no rudpbuffer_free after write
		while (p2pblock_isfull(reqblk))
			reqblk = p2pcache_nextblk(&sched->cache, reqblk);
		
		if (sched->reqblk == NULL)
			sched->reqblk = reqblk;
		else if (sched->reqblk != reqblk) {
			sched->reqblk = reqblk;
			p2psched_block_req(sched);
		}
		return 0;
	}
	}

	rudpbuffer_free(buffer);
	return 0;
}

static void p2psched_blkjob(void *arg)
{
	p2psched_t *sched = (p2psched_t *)arg;
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	p2ppeer_t *peer = NULL;
	uint32_t curtime = getcurtime_ms();
	int reqms = curtime - sched->reqtime;
	int rspms = curtime - sched->rsptime;

	log_debug("request block %llu timeout, uid:%llu cid:%d status:%d seq:%d reqtime:%d rsptime:%d %p",
		sched->reqblk ? sched->reqblk->bm.startpackid : 0, sched->requid, sched->cid, sched->status, p2psched_reqnum(sched), reqms, rspms, sched);

	if (reqms >= mgmt->param.blktimeout && rspms >= mgmt->param.blktimeout) {
		if (sched->requid != 0)
			p2psched_droppeer(sched, sched->requid, curtime);
		p2psched_block_req(sched);
	}
	else {
		if (sched->status != STATUS_CLOSING) {
			int blkms = mgmt->param.blktimeout - ((reqms > rspms) ? rspms : reqms);
			struct timeval tv = { blkms / 1000, blkms % 1000 * 1000 };
			event_add(&sched->blktimer, &tv);
			if (sched->status == STATUS_CLOSING) event_del(&sched->blktimer);
		}
	}
	p2psched_unref(sched);
}

static void p2psched_blktimer(evutil_socket_t fd, short event, void *arg)
{
	p2psched_t *sched = (p2psched_t *)arg;
	p2pmgmt_t *mgmt = (p2pmgmt_t *)sched->p2pmgmt;

	p2psched_ref(sched);
	//rudpworker_addjob(mgmt->wp, p2psched_blkjob, sched, 0);
	p2psched_blkjob(sched);
}

static void p2psched_hlojob(void *arg)
{
	p2psched_t *sched = (p2psched_t *)arg;
	p2ppeer_t *peer, *nextpeer;
	DLIST_head(p2ppeer_t) lt;

	DLIST_INIT(lt);

	pthread_mutex_lock(&sched->ht_lck);
	DLIST_FOREACH(lhpeer, sched->ltupper, peer, nextpeer) {
		if (peer->usesess != NULL) 
			continue;
		HASH_DELETE(hhpeer, sched->htpeer, peer);
		DLIST_DEL(lhpeer, sched->ltupper, peer);
		DLIST_ADD(lhpeer, lt, peer);
	}
	pthread_mutex_unlock(&sched->ht_lck);

	log_debug("hello cid:%d ack:%d noack:%d status:%d reqnum:%d %p", sched->cid,
		DLIST_COUNT(sched->ltupper), DLIST_COUNT(lt), sched->status, p2psched_reqnum(sched), sched);

	DLIST_FOREACH(lhpeer, lt, peer, nextpeer) {
		p2ppeer_destroy(peer);
	}
	p2psched_unref(sched);
}

static void p2psched_hlotimer(evutil_socket_t fd, short event, void *arg)
{
	p2psched_t *sched = (p2psched_t *)arg;
	p2pmgmt_t *mgmt = (p2pmgmt_t *)sched->p2pmgmt;

	p2psched_ref(sched);
	//rudpworker_addjob(mgmt->wp, p2psched_hlojob, sched, 0);
	p2psched_hlojob(sched);
}

static void p2psched_trkjob(void *arg)
{
	p2psched_t *sched = (p2psched_t *)arg;
	p2pmgmt_t *mgmt = sched->p2pmgmt;
	p2ppeer_t *peer, *nextpeer;
	uint32_t curtime = getcurtime_ms();
	struct timeval tv = { mgmt->param.trkinter / 1000,
						mgmt->param.trkinter % 1000 * 1000 };

	log_debug("login trksess:%p status:%d reqnum:%d %p",
		sched->trksess, sched->status, p2psched_reqnum(sched), sched);

	pthread_mutex_lock(&sched->ht_lck);
	DLIST_FOREACH(lhpeer, sched->ltupper, peer, nextpeer) {
		if (peer->waiting != 0 && peer->waiting != -1 &&
			(int32_t)(curtime - peer->waiting) > mgmt->param.blktimeout)
			peer->waiting = 0;
	}
	pthread_mutex_unlock(&sched->ht_lck);

	p2psched_login_req(sched);

	if (sched->status != STATUS_CLOSING) {
		event_add(&sched->trktimer, &tv);
		if (sched->status == STATUS_CLOSING) event_del(&sched->trktimer);
	}
	p2psched_unref(sched);
}

static void p2psched_trktimer(evutil_socket_t fd, short event, void *arg)
{
	p2psched_t *sched = (p2psched_t *)arg;
	p2pmgmt_t *mgmt = (p2pmgmt_t *)sched->p2pmgmt;

	p2psched_ref(sched);
	//rudpworker_addjob(mgmt->wp, p2psched_trkjob, sched, 0);
	p2psched_trkjob(sched);
}

static void p2psched_cachejob(void *arg)
{
	p2ppeer_t *peer = (p2ppeer_t *)arg;
	p2psched_t *sched = peer->p2psched;
	p2pmgmt_t *mgmt = (p2pmgmt_t *)sched->p2pmgmt;
	uint64_t packid = peer->waitblk.bm.startpackid + peer->waitblk.bm.bitstart;
	rudpsession_t *peersess;
	int ipack;
	p2pmsg_pack_t pack;
	char ackbuffer[MAX_MTU], *ptr;
	uint32_t curtime, waiting;

	waiting = peer->waiting;
	if (peer->waiting == 0 || peer->waiting == -1) {
		p2ppeer_unref(peer);
		return;
	}

	ipack = p2pcache_read(&sched->cache, packid, &pack);
	if (ipack < 0) {
		p2ppeer_unref(peer);
		return;
	}
	
	peersess = p2ppeer_getusesess(peer);
	if (peersess == NULL || rudpsess_cansend(peersess) <= 0) {
		p2ppeer_unref(peer);
		return;
	}
	
	curtime = getcurtime_ms();
	if (peer->waiting == waiting) { //TODO: new blk req
		peer->waitblk.bm.bitstart++;
		peer->waiting = (curtime != 0 && curtime != -1) ? curtime : 1;
	}

	p2psched_block_ackdata(pack, P2P_CMD_ACK_PACK, &peer->waitreq, sched);
	ptr = p2pmsg_pack_encode(ackbuffer, &pack);
	p2pcache_freebuffer(pack.data);
	rudpsess_send(peersess, ackbuffer, ptr - ackbuffer, curtime);
	rudpsess_unref(peersess);

	p2ppeer_unref(peer);
}

static int p2psched_cachecb(p2pcache_t *cache, uint64_t packid)
{
	p2psched_t *sched = cache->p2psched;
	p2pmgmt_t *mgmt = (p2pmgmt_t *)sched->p2pmgmt;
	p2ppeer_t *peer, *nextpeer;
	uint32_t curtime = getcurtime_ms();
	p2ppeer_t *prepeers[100];
	p2ppeer_t **peers = prepeers;
	int i, peernum = 0;

	pthread_mutex_lock(&sched->ht_lck);
	if (DLIST_COUNT(sched->ltlower) > 100) {
		peers = kcalloc(DLIST_COUNT(sched->ltlower), sizeof(p2ppeer_t *));
	}
	DLIST_FOREACH(lhpeer, sched->ltlower, peer, nextpeer) {
		if (peer->waiting == 0 || peer->waiting == -1) {
			continue;
		}
		if ((int32_t)(curtime - peer->waiting) > (int32_t)mgmt->param.blktimeout ||
			peer->waitblk.bm.bitstart >= peer->waitblk.bm.bitsize) {
			peer->waiting = 0;
			continue;
		}
		if (packid != peer->waitblk.bm.startpackid + peer->waitblk.bm.bitstart ||
			p2pbitmap_get(&peer->waitblk.bm, peer->waitblk.bm.bitstart)) {
			continue;
		}
		p2ppeer_ref(peer);
		//rudpworker_addjob(mgmt->wp, p2psched_cachejob, peer, 0);
		peers[peernum++] = peer;
	}
	pthread_mutex_unlock(&sched->ht_lck);

	for (i = 0; i < peernum; i++) {
		p2psched_cachejob(peers[i]);
	}
	if (peers != prepeers) kfree(peers);
	return 0;
}

p2psched_t *p2psched_new(void *p2pmgmt, uint32_t cid, const char *puship, uint16_t pushport)
{
	p2pmgmt_t *mgmt = p2pmgmt;
	p2psched_t *sched = (p2psched_t *)kcalloc(1, sizeof(p2psched_t));
	struct timeval tv = { mgmt->param.trkinter / 1000,
						mgmt->param.trkinter % 1000 * 1000 };

	sched->refcnt = 2;
	sched->reqseq = 0;
	sched->cid = cid;
	p2pcache_init(&sched->cache, &mgmt->param, p2psched_cachecb, sched);
	p2pm3u8_init(&sched->m3u8, sched);
	sched->psh = ts_stream_get_handle();
	sched->psh->fn_init(sched->psh);
	pthread_mutex_init(&sched->ht_lck, 0);
	DLIST_INIT(sched->ltupper);
	DLIST_INIT(sched->ltlower);
	sched->htpeer = NULL;
	sched->status = STATUS_INIT;

	p2pmgmt_ref(mgmt);
	sched->p2pmgmt = mgmt;
	sched->peer.uid = mgmt->uid;

	sched->p2psock = rudpsock_new(mgmt->wp, mgmt->ip[0] ? mgmt->ip : "0.0.0.0",
			(mgmt->port != 0) ? (mgmt->port + sched->cid) : 0, sizeof(uint64_t),
			mgmt->param.maxidle, mgmt->param.mtu - RUDP_OVERHEAD, mgmt->param.interval, mgmt->param.minrto,
			mgmt->param.fastresend, mgmt->param.wndsize, mgmt->param.xmitmax, mgmt->param.sndtimeout,
			RUDP_NOTIFY_NEXT, p2psched_recvcb, p2psched_notifycb, p2psched_closecb, p2psched_destroycb, sched);

	sched->peer.lanip = mgmt->lanip;
	sched->peer.lanport = sched->p2psock->port;

	sched->trksess = rudpsock_connect(sched->p2psock, inet_addr(mgmt->trkip), mgmt->trkport);
	if (pushport > 0)
		sched->tcpsrv = p2ptcpsrv_new(sched, puship, pushport);

	event_assign(&sched->trktimer, sched->p2psock->evbase, -1, 0, p2psched_trktimer, sched);
	event_assign(&sched->blktimer, sched->p2psock->evbase, -1, 0, p2psched_blktimer, sched);
	event_assign(&sched->hlotimer, sched->p2psock->evbase, -1, 0, p2psched_hlotimer, sched);

	p2psched_login_req(sched);
	event_add(&sched->trktimer, &tv);

	return sched;
}

void p2psched_destroy(p2psched_t *sched)
{
	p2ppeer_t *peer, *nextpeer;
	DLIST_head(p2ppeer_t) lt;
	rudpsession_t * trksess;

	DLIST_INIT(lt);

	sched->status = STATUS_CLOSING;
	event_del(&sched->trktimer);
	event_del(&sched->blktimer);
	event_del(&sched->hlotimer);

	if (sched->tcpsrv != NULL)
		p2ptcpsrv_destroy(sched->tcpsrv);

	pthread_mutex_lock(&sched->ht_lck);
	HASH_ITER(hhpeer, sched->htpeer, peer, nextpeer) {
		HASH_DELETE(hhpeer, sched->htpeer, peer);
		if (peer->upper) DLIST_DEL(lhpeer, sched->ltupper, peer);
		else DLIST_DEL(lhpeer, sched->ltlower, peer);
		DLIST_ADD(lhpeer, lt, peer);
	}
	trksess = sched->trksess;
	sched->trksess = NULL;
	pthread_mutex_unlock(&sched->ht_lck);

	DLIST_FOREACH(lhpeer, lt, peer, nextpeer) {
		p2ppeer_destroy(peer);
	}

	if (trksess != NULL)
		rudpsess_close(trksess, 1);
	rudpsock_close(sched->p2psock);
	p2psched_unref(sched);
}
