#include "rudpsess.h"
#include "rudppeer.h"
#include "rudpsock.h"
#include "rudpworker.h"
#include "app_log.h"

int rudpsess_ref(rudpsession_t *session)
{
	return _sync_add32(&session->refcnt, 1);
}

int rudpsess_unref(rudpsession_t *session)
{
	int refcnt = _sync_add32(&session->refcnt, -1);
	if (refcnt != 1)
		return refcnt;

	rudppeer_t *peer = session->rudppeer;

	log_debug("session freed! %x/%x %p %p %p %p %s:%d\n",
		session->mysessid, session->peersessid, session, session->rudppeer, session->rudpsock, session->data,
		inet_ntoa(((struct sockaddr_in *)&peer->addr)->sin_addr), ntohs(((struct sockaddr_in *)&peer->addr)->sin_port));

	ikcp_release(session->kcp);

	rudppeer_unref(session->rudppeer);  //session
	rudpsock_unref(session->rudpsock);  //session
	kfree(session);
	return refcnt;
}

static void rudpsess_closejob(void *rudpsess)
{
	rudpsession_t *session = rudpsess;
	rudpsocket_t *rudp = session->rudpsock;

	rudp->closecb(session, rudp->data);
	rudpsess_unref(session);
}

void rudpsess_close(rudpsession_t *session, int external)
{
	rudpsocket_t *rudp = session->rudpsock;
	rudppeer_t *peer = session->rudppeer;

	log_debug("session close! %x/%x %p %p %p %p %s:%d closing:%d ref:%d\n",
		session->mysessid, session->peersessid, session, session->rudppeer, session->rudpsock, session->data,
		inet_ntoa(((struct sockaddr_in *)&peer->addr)->sin_addr), ntohs(((struct sockaddr_in *)&peer->addr)->sin_port), session->closing, session->refcnt);

	pthread_mutex_lock(&rudp->ht_lck);
	if (session->closing) {
		pthread_mutex_unlock(&rudp->ht_lck);
		rudpsess_rstcmd(session);
		if (external) rudpsess_unref(session);
		return;
	}
	session->closing = 1;
	DLIST_DEL(lhsess, peer->ltsess, session);
	if (DLIST_IS_EMPTY(peer->ltsess)) {
		if (rudp->htpeer != NULL)
			HASH_DELETE(hhpeer, rudp->htpeer, peer);
		rudppeer_unref(peer);  //rudp->htpeer
	}
	if (rudp->htsess != NULL && session->mysessid != 0)
		HASH_DELETE(hhsess, rudp->htsess, session);
	pthread_mutex_unlock(&rudp->ht_lck);

	rudpsess_rstcmd(session);
	event_del(&session->acktimer);
	event_del(&session->segtimer);

	if (external || !rudp->closecb)
		rudpsess_unref(session);  //external unref
	else {
		rudpsess_ref(session);
		//rudpworker_addjob(rudp->wp, rudpsess_closejob, session, 0);
		rudpsess_closejob(session);
	}

	rudpsess_unref(session);  //peer->ltsess & rudp->htsess
}

static int rudpkcp_rstcmd(rudpsocket_t *rudp, struct sockaddr *peeraddr, uint32_t conv)
{
	char rstcmd[RUDP_OVERHEAD];
	int len;

	len = ikcp_rstcmd(rstcmd, conv); //reset session
	return sendto(rudp->sockfd, rstcmd, len, 0, peeraddr, sizeof(*peeraddr));
}

int rudpsess_rstcmd(rudpsession_t *session)
{
	rudppeer_t *peer = session->rudppeer;
	return rudpkcp_rstcmd(session->rudpsock, &peer->addr, session->kcp->conv);
}

int rudpsess_oobcmd(rudpsession_t *session, const char *data, int len)
{
	rudppeer_t *peer = session->rudppeer;
	rudpsocket_t *rudp = session->rudpsock;
	char oobcmd[MAX_MTU];

	if (len + RUDP_OVERHEAD > MAX_MTU)
		return -1;
	len = ikcp_oobcmd(oobcmd, session->kcp->conv, data, len);
	return sendto(rudp->sockfd, oobcmd, len, 0, &peer->addr, sizeof(peer->addr));
}

static void rudpsess_ntfsuccjob(void *kcpseg)
{
	IKCPSEG *seg = kcpseg;
	ikcpcb *kcp = seg->kcp;
	rudpsession_t *session = kcp->user;
	rudpsocket_t *rudp = session->rudpsock;

	rudp->notifycb(session, seg->data, seg->len, RUDP_NOTIFY_SUCC, rudp->data);
	ikcp_segment_delete(kcp, seg);
	rudpsess_unref(session);
}

static void rudpsess_ntffailjob(void *kcpseg)
{
	IKCPSEG *seg = kcpseg;
	ikcpcb *kcp = seg->kcp;
	rudpsession_t *session = kcp->user;
	rudpsocket_t *rudp = session->rudpsock;

	rudp->notifycb(session, seg->data, seg->len, RUDP_NOTIFY_FAIL, rudp->data);
	ikcp_segment_delete(kcp, seg);

	rudpstat_fail(&session->stat);
	rudpstat_fail(&rudp->stat);
	rudpsess_unref(session);
}

static void rudpsess_ntfnextjob(void *rudpsess)
{
	rudpsession_t *session = rudpsess;
	rudpsocket_t *rudp = session->rudpsock;

	rudp->notifycb(session, NULL, 0, RUDP_NOTIFY_NEXT, rudp->data);
	rudpsess_unref(session);
}

static int rudpkcp_notify(int type, IKCPSEG *seg, ikcpcb *kcp, void *data)
{
	rudpsession_t *session = (rudpsession_t *)data;
	rudpsocket_t *rudp = session->rudpsock;
	
	if (!rudp->notifycb) {
		if (seg) ikcp_segment_delete(kcp, seg);
		return 0;
	}

	if (type == RUDP_NOTIFY_SUCC) {
		rudpsess_ref(session);
		//rudpworker_addjob(rudp->wp, rudpsess_ntfsuccjob, seg, 0);
		rudpsess_ntfsuccjob(seg);
	}
	else if (type == RUDP_NOTIFY_FAIL) {
		rudpsess_ref(session);
		//rudpworker_addjob(rudp->wp, rudpsess_ntffailjob, seg, 0);
		rudpsess_ntffailjob(seg);
	}
	else if (type == RUDP_NOTIFY_NEXT) {
		rudpsess_ref(session);
		//rudpworker_addjob(rudp->wp, rudpsess_ntfnextjob, session, 0);
		rudpsess_ntfnextjob(session);
		if (seg) ikcp_segment_delete(kcp, seg);
	}
	else if (seg) 
		ikcp_segment_delete(kcp, seg);
	return 0;
}

static int rudpkcp_output(const char *buf, int len, ikcpcb *kcp, void *data)
{
	rudpsession_t *session = (rudpsession_t *)data;
	rudppeer_t *peer = session->rudppeer;
	rudpsocket_t *rudp = session->rudpsock;
	int ret;

	rudpstat_send(&session->stat, len);
	rudpstat_send(&rudp->stat, len);

	if (peer->sockfd != INVALID_SOCKET)
		ret = send(peer->sockfd, buf, len, 0);
	else
		ret = sendto(rudp->sockfd, buf, len, 0, &peer->addr, sizeof(peer->addr));
	if (ret <= 0)
		log_warn("send failed:%d %u", ret, sockerr);
	return ret;
}

static void rudpkcp_writelog(const char *log, struct IKCPCB *kcp, void *user)
{
	log_debug("%p %s", user, log);
}

static void rudpsess_ackjob(void *arg)
{
	rudpsession_t *session = (rudpsession_t *)arg;
	rudppeer_t *peer = session->rudppeer;
	rudpsocket_t *rudp = session->rudpsock;
	ikcpcb *kcp = session->kcp;
	uint32_t curtime = getcurtime_ms();
	struct timeval tv = { 0, 0 };
	uint32_t nextms;
	int close_once = 0;

	nextms = ikcp_flushack(kcp, curtime, 0);
	if (!session->closing) {
		event_add(&session->acktimer, rudptv_set(tv, nextms));
		if (session->closing) event_del(&session->acktimer);
	}
	
	if (curtime >= session->chktime + RUDPCHK_INTERVAL) {
		session->chktime = curtime;
		rudpstat_statis(&session->stat, curtime);
	}

	if (ikcp_idletime(session->kcp) > rudp->sessidle || ikcp_broken(session->kcp)) {
		pthread_mutex_lock(&rudp->ht_lck);
		if (!session->closing) {
			session->closing = 1;
			close_once = 1;
			DLIST_DEL(lhsess, peer->ltsess, session);
			if (DLIST_IS_EMPTY(peer->ltsess)) {
				HASH_DELETE(hhpeer, rudp->htpeer, peer);
				rudppeer_unref(peer);  //rudp->htpeer
			}
			if (session->mysessid != 0)
				HASH_DELETE(hhsess, rudp->htsess, session);
			rudpsess_unref(session);  //peer->ltsess & rudp->htsess
		}
		pthread_mutex_unlock(&rudp->ht_lck);

		rudpsess_rstcmd(session);
		event_del(&session->acktimer);
		event_del(&session->segtimer);

		if (close_once && rudp->closecb) {
			rudpsess_ref(session);
			//rudpworker_addjob(rudp->wp, rudpsess_closejob, session, 0);
			rudpsess_closejob(session);
		}
	}

	rudpsess_unref(session);
}

static void rudpsess_acktimer(evutil_socket_t fd, short event, void *arg)
{
	rudpsession_t *session = (rudpsession_t *)arg;
	rudpsocket_t *rudp = session->rudpsock;

	rudpsess_ref(session);
	//rudpworker_addjob(rudp->wp, rudpsess_ackjob, session, 1);
	rudpsess_ackjob(session);
}

static void rudpsess_segjob(void *arg)
{
	rudpsession_t *session = (rudpsession_t *)arg;
	ikcpcb *kcp = session->kcp;
	uint32_t curtime = getcurtime_ms();
	struct timeval tv = { 0, 0 };
	uint32_t nextms;

	nextms = ikcp_flushseg(kcp, curtime);
	if (!session->closing) {
		event_add(&session->segtimer, rudptv_set(tv, nextms));
		if (session->closing) event_del(&session->segtimer);
	}

	rudpsess_unref(session);
}

static void rudpsess_segtimer(evutil_socket_t fd, short event, void *arg)
{
	rudpsession_t *session = (rudpsession_t *)arg;
	rudpsocket_t *rudp = session->rudpsock;

	rudpsess_ref(session);
	//rudpworker_addjob(rudp->wp, rudpsess_segjob, session, 1);
	rudpsess_segjob(session);
}

//find or create a session for the peer
rudpsession_t *rudpsess_get(void *rudpsock,
		struct sockaddr *peeraddr, uint32_t peerconv, uint32_t curtime, int flag)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	rudpsession_t *session, *nextsess;
	rudppeer_t *peer;
	struct timeval tv = { 0, 0 };
	uint32_t mytype = CONV_PEERTYPE(peerconv);
	uint32_t mysessid = CONV_PEERSESSID(peerconv);
	uint32_t mymask = CONV_PEERMASK(peerconv);
	uint32_t peersessid = CONV_MYSESSID(peerconv);
	uint32_t peermask = CONV_MYMASK(peerconv);
	uint32_t myconv = mytype | mysessid | peersessid;
	uint32_t peer_is_chg = 0, i;
	
	if (mysessid != 0) { //peer has my id
		pthread_mutex_lock(&rudp->ht_lck);
		HASH_FIND(hhsess, rudp->htsess, &mysessid, sizeof(mysessid), session);
		if (session == NULL) {
			pthread_mutex_unlock(&rudp->ht_lck);
			if (flag != RUDPFLAG_CLOSE)
				rudpkcp_rstcmd(rudpsock, peeraddr, myconv);
			return NULL;
		}
		session->peersessid = peersessid;
		session->kcp->conv = myconv;
		if (flag == RUDPFLAG_CLOSE) {
			pthread_mutex_unlock(&rudp->ht_lck);
			rudpsess_close(session, 0);
			return NULL;
		}
		peer = session->rudppeer;
		if (memcmp(&peer->addr, peeraddr, RUDPKEY_ADDRLEN)) {
			HASH_DELETE(hhpeer, rudp->htpeer, peer);
			peer->addr = *peeraddr; //update peer
			HASH_ADD(hhpeer, rudp->htpeer, addr, RUDPKEY_ADDRLEN, peer);
			peer_is_chg = 1;
		}
		rudpsess_ref(session);
		pthread_mutex_unlock(&rudp->ht_lck);
		if (peer_is_chg) {
			if (peer->sockfd != INVALID_SOCKET) {
				if (connect(peer->sockfd, &peer->addr, sizeof(peer->addr)) < 0) {
					SOCKET sockfd = peer->sockfd;
					peer->sockfd = INVALID_SOCKET;
					closesocket(sockfd);
				}
			}
		}
		return session;
	}

	peer = rudppeer_get(rudpsock, peeraddr, curtime, flag);
	if (peer == NULL)
		return NULL;

	pthread_mutex_lock(&rudp->ht_lck);
	pthread_mutex_lock(&peer->lt_lck);
	if (peersessid == 0 && flag == RUDPFLAG_SEND)
		session = DLIST_HEAD(peer->ltsess);
	else DLIST_FOREACH(lhsess, peer->ltsess, session, nextsess) {
		if (session->peersessid == peersessid)
			break;
	}
	pthread_mutex_unlock(&peer->lt_lck);
	if (session != NULL) {
		rudpsess_ref(session);
		pthread_mutex_unlock(&rudp->ht_lck);
		rudppeer_unref(peer);
		if (flag == RUDPFLAG_CLOSE) {
			rudpsess_close(session, 0);
			return NULL;
		}
		return session;
	}

	if (flag == RUDPFLAG_CLOSE) {
		pthread_mutex_unlock(&rudp->ht_lck);
		rudppeer_unref(peer);
		return NULL;
	}

	//session not found, create one
	for (i = 0; i < mymask && i < 256; i++) {
		mysessid = CONV_NEWSESSID(mytype, rudp->cseq, rudp->sseq);
		if (mysessid != 0) {
			HASH_FIND(hhsess, rudp->htsess, &mysessid, sizeof(mysessid), session);
			if (session == NULL)
				break;
			mysessid = 0; //clear unusable
		}
	}
	myconv = mytype | mysessid | peersessid;

	session = (rudpsession_t *)kcalloc(1, sizeof(rudpsession_t) + rudp->sesslen);
	session->peersessid = peersessid;
	session->mysessid = mysessid;
	session->kcp = ikcp_create(myconv, peermask, session, curtime);
	session->kcp->ntftype = rudp->ntftype;
	session->kcp->output = rudpkcp_output;
	session->kcp->notify = rudpkcp_notify;
	session->kcp->writelog = rudpkcp_writelog;
	session->kcp->logmask = IKCP_LOG_ERROR; // | IKCP_LOG_OUTPUT | IKCP_LOG_TRACE; // | IKCP_LOG_RESEND | IKCP_LOG_SEND | IKCP_LOG_INPUT | IKCP_LOG_OUT_ACK | IKCP_LOG_IN_ACK | IKCP_LOG_IN_DATA;
	session->kcp->maxmtu = rudp->maxmtu;
	ikcp_wndsize(session->kcp, rudp->wndsize, rudp->wndsize);
	ikcp_nodelay(session->kcp, 1, 10, 0, 1);
	session->kcp->interval = rudp->interval;
	session->kcp->rx_minrto = rudp->minrto;
	session->kcp->fastresend = rudp->fastresend <= 0 ? RUDP_FASTRESEND : rudp->fastresend;
	session->kcp->dead_link = rudp->xmitmax;
	session->kcp->snd_timeout = rudp->sndtimeout;
	session->chktime = curtime;
	rudpstat_init(&session->stat, curtime);
	session->closing = 0;
	if (rudp->sesslen > 0) 
		session->data = (char *)session + sizeof(rudpsession_t);
	session->refcnt = 2; //1:self + 1:peer->ltsess & rudp->htsess
	pthread_mutex_lock(&peer->lt_lck);
	DLIST_ADD(lhsess, peer->ltsess, session);
	pthread_mutex_unlock(&peer->lt_lck);
	session->rudppeer = peer;
	if (session->mysessid != 0)
		HASH_ADD(hhsess, rudp->htsess, mysessid, sizeof(session->mysessid), session);
	session->rudpsock = rudpsock;
	rudpsock_ref(rudp);  //session
	pthread_mutex_unlock(&rudp->ht_lck);

	event_assign(&session->acktimer, peer->evbase, -1, 0, rudpsess_acktimer, session);
	event_add(&session->acktimer, rudptv_set(tv, rudp->interval));

	event_assign(&session->segtimer, peer->evbase, -1, 0, rudpsess_segtimer, session);
	event_add(&session->segtimer, rudptv_set(tv, rudp->interval));

	log_debug("session new %x/%x %p %p %p %s:%d\n",
		session->mysessid, session->peersessid, session, session->rudppeer, session->rudpsock,
		inet_ntoa(((struct sockaddr_in *)peeraddr)->sin_addr), ntohs(((struct sockaddr_in *)peeraddr)->sin_port));
	return session;
}

// return times to call next send, -1:error
int rudpsess_send(rudpsession_t *session, const char *buf, int len, uint32_t curtime)
{
	rudpsocket_t *rudp = session->rudpsock;
	ikcpcb *kcp = session->kcp;
	int ret;

	if (session->closing)
		return -1;

	ret = ikcp_send(kcp, buf, len, curtime);
	return ret < 0 ? -1 : ret;
}

//return rto of the session
uint32_t rudpsess_rto(rudpsession_t *session)
{
	return session->kcp->rx_rto;
}

int rudpsess_sendrate(rudpsession_t *session)
{
	return session->stat.sendrate;
}

int rudpsess_recvrate(rudpsession_t *session)
{
	return session->stat.recvrate;
}

int rudpsess_isvalid(rudpsession_t *session)
{
	return session->closing == 0 ? 1 : 0;
}

int rudpsess_cansend(rudpsession_t *session)
{
	if (session->closing)
		return 0;
	return ikcp_cansend(session->kcp);
}
