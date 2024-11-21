#include "rudp.h"

#define P2P_MAXIDLE      RUDPSESS_TIMEOUT
#define P2P_MTU          MAX_MTU
#define P2P_INTERVAL     10
#define P2P_MINRTO       10
#define P2P_FASTRESEND   0
#define P2P_WNDSIZE      1024
#define P2P_XMITMAX      120
#define P2P_SNDTIMEOUT   900

int rudp_init()
{
	return rudpsock_init();
}

void rudp_cleanup()
{
	rudpsock_cleanup();
}

void *rudp_newsock(rudpworker_pool_t *wp, const char *ip, short port, void *arg,
		fn_recvcb *recvcb, fn_notifycb *notifycb, fn_closecb *closecb, fn_destroycb *destroycb)
{
	return rudpsock_new(wp, ip ? ip : "0.0.0.0", port, 0, P2P_MAXIDLE,
		P2P_MTU, P2P_INTERVAL, P2P_MINRTO, P2P_FASTRESEND, P2P_WNDSIZE, P2P_XMITMAX,
		P2P_SNDTIMEOUT, RUDP_NOTIFY_FAIL, recvcb, notifycb, closecb, destroycb, arg);
}

int rudp_sendto(void *rudpsock, char *data, int len, struct sockaddr *addr, void *arg)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	uint32_t curtime = getcurtime_ms();
	rudpsession_t *session;
	int cansend = 0;

	session = rudpsess_get(rudp, addr, RUDPCONV_START, curtime, RUDPFLAG_SEND);
	if (session == NULL)
		return -1;
	session->data = arg;
	cansend = rudpsess_send(session, data, len, curtime);
	rudpsess_unref(session);
	return cansend;
}

void rudp_closesock(void *rudpsock)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	rudpsock_close(rudp);
}

int rudp_closeconn(void *rudpsock, struct sockaddr *addr)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	rudppeer_t *peer;
	rudpsession_t *session, *sessnext;
	DLIST_head(rudpsession_t) ltsess;
	int len;

	pthread_mutex_lock(&rudp->ht_lck);
	HASH_FIND(hhpeer, rudp->htpeer, addr, RUDPKEY_ADDRLEN, peer);
	if (peer == NULL) {
		pthread_mutex_unlock(&rudp->ht_lck);
		return 0;
	}
	DLIST_FOREACH(lhsess, peer->ltsess, session, sessnext) {
		session->closing = 1;
		if (session->mysessid != 0)
			HASH_DELETE(hhsess, rudp->htsess, session);
	}
	DLIST_COPY(ltsess, peer->ltsess);
	DLIST_INIT(peer->ltsess);
	HASH_DELETE(hhpeer, rudp->htpeer, peer);
	rudppeer_unref(peer);
	pthread_mutex_unlock(&rudp->ht_lck);

	len = DLIST_COUNT(ltsess);
	DLIST_FOREACH(lhsess, ltsess, session, sessnext) {
		rudpsess_rstcmd(session);
		event_del(&session->acktimer);
		event_del(&session->segtimer);
		if (rudp->closecb)
			rudp->closecb(session, rudp->data);
		rudpsess_unref(session);
	}
	return len;
}

int rudp_recvrate(void *rudpsock, struct sockaddr *addr)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	rudppeer_t *peer;
	rudpsession_t *session;
	int recvrate = 0;

	pthread_mutex_lock(&rudp->ht_lck);
	HASH_FIND(hhpeer, rudp->htpeer, addr, RUDPKEY_ADDRLEN, peer);
	if (peer != NULL) {
		session = DLIST_HEAD(peer->ltsess);
		if (session != NULL)
			recvrate = rudpsess_recvrate(session);
	}
	pthread_mutex_unlock(&rudp->ht_lck);
	return recvrate;
}

int rudp_sendrate(void *rudpsock, struct sockaddr *addr)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	rudppeer_t *peer;
	rudpsession_t *session;
	int sendrate = 0;

	pthread_mutex_lock(&rudp->ht_lck);
	HASH_FIND(hhpeer, rudp->htpeer, addr, RUDPKEY_ADDRLEN, peer);
	if (peer != NULL) {
		session = DLIST_HEAD(peer->ltsess);
		if (session != NULL)
			sendrate = rudpsess_sendrate(session);
	}
	pthread_mutex_unlock(&rudp->ht_lck);
	return sendrate;
}

int rudp_conrtt(void *rudpsock, struct sockaddr *addr)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	rudppeer_t *peer;
	rudpsession_t *session;
	int rtt = 0x7FFFFFFF;

	pthread_mutex_lock(&rudp->ht_lck);
	HASH_FIND(hhpeer, rudp->htpeer, addr, RUDPKEY_ADDRLEN, peer);
	if (peer != NULL) {
		session = DLIST_HEAD(peer->ltsess);
		if (session != NULL)
			rtt = rudpsess_rto(session);
	}
	pthread_mutex_unlock(&rudp->ht_lck);
	return rtt;
}
