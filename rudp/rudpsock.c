#include "rudpsock.h"
#include "app_log.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/util.h"
#include "event2/thread.h"

int rudpsock_ref(rudpsocket_t *rudp)
{
	return _sync_add32(&rudp->refcnt, 1);
}

int rudpsock_unref(rudpsocket_t *rudp)
{
	int refcnt = _sync_add32(&rudp->refcnt, -1);
	if (refcnt != 1) 
		return refcnt;

	log_debug("rudp freed! port:%d %p\n", rudp->port, rudp);

	if (rudp->destroycb)
		rudp->destroycb(rudp);

	rudpstat_destroy(&rudp->stat);
	pthread_mutex_destroy(&rudp->ht_lck);
	closesocket(rudp->sockfd);
	if (rudp->wp->owner == rudp)
		rudpworker_destroy(rudp->wp); //private worker pool
	kfree(rudp);
	return refcnt;
}

void rudpsock_close(rudpsocket_t *rudp)
{
	rudpsession_t *session, *sessnext;
	rudppeer_t *peer, *peernext;
	DLIST_head(rudpsession_t) ltsess;

	DLIST_INIT(ltsess);
	pthread_mutex_lock(&rudp->ht_lck);
	if (rudp->closing) {
		pthread_mutex_unlock(&rudp->ht_lck);
		return;
	}
	HASH_ITER(hhpeer, rudp->htpeer, peer, peernext) {
		pthread_mutex_lock(&peer->lt_lck);
		DLIST_FOREACH(lhsess, peer->ltsess, session, sessnext) {
			session->closing = 1;
			if (session->mysessid != 0)
				HASH_DELETE(hhsess, rudp->htsess, session);
			DLIST_ADD(lhsess, ltsess, session);
		}
		DLIST_INIT(peer->ltsess);
		pthread_mutex_unlock(&peer->lt_lck);
		HASH_DELETE(hhpeer, rudp->htpeer, peer);
		rudppeer_unref(peer);  //rudp->htpeer
	}
	rudp->closing = 1;
	pthread_mutex_unlock(&rudp->ht_lck);

	DLIST_FOREACH(lhsess, ltsess, session, sessnext) {
		rudpsess_rstcmd(session);
		event_del(&session->acktimer);
		event_del(&session->segtimer);
		if (rudp->closecb)
			rudp->closecb(session, rudp->data);
		rudpsess_unref(session);  //peer->ltsess & rudp->htsess
	}

	event_del(&rudp->chktimer);  //would wait for the last callback to finish
#if !(WINSOCK_IOCP)
	event_del(&rudp->evsock);
#endif

	rudpsock_unref(rudp);
}

static void rudpsock_chkjob(void *arg)
{
	rudpsocket_t *rudp = (rudpsocket_t *)arg;
	uint32_t curtime = getcurtime_ms();
	struct timeval tv;
	rudpsession_t *session, *sessnext;
	rudppeer_t *peer, *peernext;

	rudpstat_statis(&rudp->stat, curtime);
	log_debug("rudp sessnum:%d sendrate:%d recvrate:%d failcnt:%u port:%d %p",
		rudpsock_sessnum(rudp), rudpsock_sendrate(rudp), rudpsock_recvrate(rudp), rudpsock_failcnt(rudp), rudp->port, rudp);

	pthread_mutex_lock(&rudp->ht_lck);
	HASH_ITER(hhpeer, rudp->htpeer, peer, peernext) {
		pthread_mutex_lock(&peer->lt_lck);
		DLIST_FOREACH(lhsess, peer->ltsess, session, sessnext) {
			log_debug("rudp session:%x/%x %p rtt=%d/%d %u/%u/%d %u/%u/%d %d %p", session->mysessid, session->kcp->conv,
				session, session->kcp->rx_rto, session->kcp->ssthresh, session->kcp->rcv_succ, session->kcp->rcv_total,
				session->kcp->rcv_total - session->kcp->rcv_succ, session->kcp->snd_succ, session->kcp->snd_total,
				session->kcp->rcv_total - session->kcp->rcv_succ, rudp->port, rudp);
		}
		pthread_mutex_unlock(&peer->lt_lck);
	}
	pthread_mutex_unlock(&rudp->ht_lck);

	if (!rudp->closing) {
		event_add(&rudp->chktimer, rudptv_set(tv, RUDPCHK_INTERVAL));
		if (rudp->closing) event_del(&rudp->chktimer);
	}
	rudpsock_unref(rudp);
}

static void rudpsock_chktimer(evutil_socket_t fd, short event, void *arg)
{
	rudpsocket_t *rudp = (rudpsocket_t *)arg;
	rudpsock_ref(rudp);
	//rudpworker_addjob(rudp->wp, rudpsock_chkjob, rudp, 1);
	rudpsock_chkjob(rudp);
}

int rudpsock_init()
{
#if _DBG_STAT
	ikcp_allocator(mstat_malloc, mstat_realloc, mstat_free);
#endif

#if defined(WINDOWS)
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
		return -1;

	SetTimerResolution(1000);

#ifndef WIN32_HAVE_CONDITION_VARIABLES
#define WIN32_HAVE_CONDITION_VARIABLES
#endif // !WIN32_HAVE_CONDITION_VARIABLES
	return evthread_use_windows_threads();
#else
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return -1;
	return evthread_use_pthreads();
#endif
}

void rudpsock_cleanup()
{
#ifdef _WIN32
	WSACleanup();
#endif
}

void rudpsock_setoobcb(rudpsocket_t *rudp, fn_oobcb *oobcb)
{
	rudp->oobcb = oobcb;
}

static void rudpsock_oobjob0(void *rudpbuf)
{
	rudpbuffer_t *rcvbuf = (rudpbuffer_t *)rudpbuf;
	rudpsocket_t *rudp = rcvbuf->rudpsock;
	rudpsession_t *session = rcvbuf->rudpsess;

	//log_debug("rudp:%p sess:%p buf:%p len:%d %x/%x", rudp, session, rcvbuf, 
	//	rcvbuf->len, session->kcp->conv & session->kcp->mask, session->kcp->conv);

	rudp->oobcb(session, rcvbuf->buf, rcvbuf->len, RUDP_OVERHEAD, rudp->data); // rudpbuffer_free by recvcb
	rudpsess_unref(session);
	rudpsock_unref(rudp);
}

static void rudpsock_recvjob0(void *rudpbuf)
{
	rudpbuffer_t *rcvbuf = (rudpbuffer_t *)rudpbuf;
	rudpsocket_t *rudp = rcvbuf->rudpsock;
	rudpsession_t *session = rcvbuf->rudpsess;

	//log_debug("rudp:%p sess:%p buf:%p len:%d %x/%x", rudp, session, rcvbuf, 
	//	rcvbuf->len, session->kcp->conv & session->kcp->mask, session->kcp->conv);

	while (session->kcp->nrcv_que > 0) {
		if (rcvbuf == NULL) rcvbuf = rudpbuffer_alloc(rudp, session);
		assert((uintptr_t)rcvbuf > 0x10000);
		rcvbuf->len = ikcp_recv(session->kcp, rcvbuf->buf, sizeof(rcvbuf->buf));  //TODO: once per frg
		if (rcvbuf->len <= 0) break;
		rudp->recvcb(session, rcvbuf->buf, rcvbuf->len, rudp->data); // rudpbuffer_free by recvcb
		rcvbuf = NULL;
	}
	if (rcvbuf != NULL) rudpbuffer_free(rcvbuf);
	rudpsess_unref(session);
	rudpsock_unref(rudp);
}

void rudpsock_recvjob1(void *rudpbuf)
{
	rudpbuffer_t *rcvbuf = (rudpbuffer_t *)rudpbuf;
	rudpsocket_t *rudp = rcvbuf->rudpsock;
	rudpsession_t *session = rcvbuf->rudpsess;
	uint32_t peerconv;
	int closing;
	uint32_t curtime = getcurtime_ms();

	closing = rudp->closing ? 1 : ikcp_chkrst(rcvbuf->buf);
	if (session == NULL) {
		peerconv = ikcp_getconv(rcvbuf->buf);
		session = rudpsess_get(rudp, &rcvbuf->addr, peerconv,
			curtime, closing ? RUDPFLAG_CLOSE : RUDPFLAG_RECV);
		if (session == NULL) {
			rudpbuffer_free(rcvbuf);
			rudpsock_unref(rudp);
			return;
		}
		rcvbuf->rudpsess = session;
	}
	else if (closing) {
		rudpsess_close(session, 0);
		rudpbuffer_free(rcvbuf);
		rudpsess_unref(session);
		rudpsock_unref(rudp);
		return;
	}

	rudpstat_recv(&session->stat, rcvbuf->len);
	rudpstat_recv(&rudp->stat, rcvbuf->len);

	//log_debug("rudp:%p sess:%p buf:%p len:%d %x/%x", rudp, session, rcvbuf,
	//	rcvbuf->len, session->kcp->conv & session->kcp->mask, session->kcp->conv);

	if (ikcp_chkoob(rcvbuf->buf)) {
		session->kcp->recvtime = curtime;
		if (rudp->oobcb != NULL) {
			assert((uintptr_t)rcvbuf > 0x10000);
			//rudpworker_addjob(rudp->wp, rudpsock_oobjob0, rcvbuf, 0);
			rudpsock_oobjob0(rcvbuf);
		}
		else {
			rudpbuffer_free(rcvbuf);
			rudpsess_unref(session);
			rudpsock_unref(rudp);
		}
		return;
	}

	ikcp_input(session->kcp, rcvbuf->buf, rcvbuf->len, curtime);
	if (rudp->recvcb != NULL && session->kcp->nrcv_que > 0)
		//rudpworker_addjob(rudp->wp, rudpsock_recvjob0, rcvbuf, 0);
		rudpsock_recvjob0(rcvbuf);
	else {
		rudpbuffer_free(rcvbuf);
		rudpsess_unref(session);
		rudpsock_unref(rudp);
	}
}

static void rudpsock_recvcb(evutil_socket_t fd, short event, void *arg)
{
	rudpsocket_t *rudp = (rudpsocket_t *)arg;
	rudpbuffer_t *rcvbuf = rudpbuffer_alloc(rudp, NULL);
	socklen_t addrlen = sizeof(struct sockaddr);

	assert((uintptr_t)rcvbuf > 0x10000);
	rcvbuf->len = recvfrom(fd, rcvbuf->buf, sizeof(rcvbuf->buf), 0, &rcvbuf->addr, &addrlen);
	if (rcvbuf->len <= 0) {
		rudpbuffer_free(rcvbuf);
		return;
	}

	//log_debug("rudp:%p buf:%p len:%d", rudp, rcvbuf, rcvbuf->len);

	rudpsock_ref(rcvbuf->rudpsock);
	//rudpworker_addjob(rudp->wp, rudpsock_recvjob1, rcvbuf, 1);
	rudpsock_recvjob1(rcvbuf);
}

#if WINSOCK_IOCP
int rudp_iocp_recvfrom(SOCKET sockfd, rudpsocket_t *rudp)
{
	LPPER_IO_OPERATION_DATA PerIoData = kcalloc(1, sizeof(PER_IO_OPERATION_DATA));
	PerIoData->rcvbuf = rudpbuffer_alloc(rudp, NULL);
	PerIoData->DataBuff.buf = PerIoData->rcvbuf->buf;
	PerIoData->DataBuff.len = sizeof(PerIoData->rcvbuf->buf);
	int flags = 0, len;
	int addrlen = sizeof(PerIoData->rcvbuf->addr);
	if (WSARecvFrom(sockfd, &PerIoData->DataBuff, 1, &len,
		&flags, &PerIoData->rcvbuf->addr, &addrlen, PerIoData, NULL) == SOCKET_ERROR) {
		DWORD err = WSAGetLastError();
		if (err != ERROR_IO_PENDING) {
			log_error("WSARecv() failed with error %d\n", err);
			kfree(PerIoData);
			return -1;
		}
	}
	return 0;
}

DWORD WINAPI rudp_iocp_loop(LPVOID lpParam)
{
	rudpsocket_t *rudp = lpParam;
	rudppeer_t *peer = NULL;
	DWORD nRecvBytes;
	LPPER_IO_OPERATION_DATA PerIoData;
	rudpbuffer_t *rcvbuf;
	int ret = 0;

	while (ret == 0 && rudp->closing == 0) {
		if (GetQueuedCompletionStatus(rudp->hIoCP, &nRecvBytes, 
			(PULONG_PTR)&peer, (LPOVERLAPPED *)&PerIoData, INFINITE) == 0) {
			DWORD err = GetLastError();
			log_error("GetQueuedCompletionStatus failed with error %d\n", err);
			if (err == ERROR_ABANDONED_WAIT_0)
				return 0;
			continue;
		}

		rcvbuf = PerIoData->rcvbuf;
		rcvbuf->len = nRecvBytes;
		kfree(PerIoData);
		if (nRecvBytes == 0) {
			log_error("Closing socket %d\n", peer ? peer->sockfd : rudp->sockfd);
			rudpbuffer_free(rcvbuf);
			continue;
		}

		ret = rudp_iocp_recvfrom(peer ? peer->sockfd: rudp->sockfd, rudp);

		rudpsock_ref(rcvbuf->rudpsock);
		//rudpworker_addjob(rudp->wp, rudpsock_recvjob1, rcvbuf, 1);
		rudpsock_recvjob1(rcvbuf);
	}
	return 0;
}

int rudp_iocp_add(rudppeer_t *peer)
{
	rudpsocket_t *rudp = peer->rudpsock;

	CreateIoCompletionPort((HANDLE)peer->sockfd, (HANDLE)rudp->hIoCP, (ULONG_PTR)peer, 0);
	return rudp_iocp_recvfrom(peer->sockfd, rudp);
}

int rudp_iocp_start(rudpsocket_t *rudp)
{
	rudpworker_pool_t *wp = rudp->wp;
	int i;

	rudp->hIoCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!rudp->hIoCP) 
		return -1;

	for (i = 0; i < wp->workernum * 2; i++) {
		pthread_t tid;
		if (pthread_create(&tid, 0, rudp_iocp_loop, rudp) != 0) {
			if (i == 0) return -1;
		}
	}

	//Associate this socket to this I/O completion port 
	CreateIoCompletionPort((HANDLE)rudp->sockfd, (HANDLE)rudp->hIoCP, (ULONG_PTR)NULL, 0);

	for (i = 0; i < wp->workernum; i++) {
		if (rudp_iocp_recvfrom(rudp->sockfd, rudp) != 0) {
			if (i == 0) return -1;
		}
	}
	return 0;
}
#endif

//init rudp instance
rudpsocket_t *rudpsock_new(rudpworker_pool_t *wp, const char *ip, short port, int sesslen, int sessidle,
		int maxmtu, int interval, int minrto, int fastresend, int wndsize, int xmitmax, int sndtimeout, int ntftype,
		fn_recvcb *recvcb, fn_notifycb *notifycb, fn_closecb *closecb, fn_destroycb *destroycb, void *data)
{
	rudpsocket_t *rudp = (rudpsocket_t *)kcalloc(1, sizeof(rudpsocket_t));
	uint32_t curtime = getcurtime_ms();
	struct sockaddr_in addr;
	struct timeval tv;
	int ret, len;
	static rudpworker_pool_t *g_wp = NULL;
	static int g_wp_init = 0;
	int so_sndbuf = wndsize * 1500;
	int so_rcvbuf = wndsize * 1500;
	int so_reuseaddr = 1;
	int so_gso = 1472;
	int so_gro = 1;

	if (wp == NULL && g_wp == NULL &&
		_sync_cas32(&g_wp_init, 0, 1) == 0) {
		g_wp = rudpworker_new(4, NULL);
	}

	rudp->wp = (wp == NULL) ? g_wp : wp;
	if (rudp->wp == NULL) {
		return kfree(rudp), NULL;
	}

	strxcpy(rudp->ip, sizeof(rudp->ip), ip, -1);
	rudp->port = port;

	rudp->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(rudp->sockfd, SOL_SOCKET, SO_SNDBUF, &so_sndbuf, sizeof(so_sndbuf));
	setsockopt(rudp->sockfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(so_rcvbuf));
	setsockopt(rudp->sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&so_reuseaddr, sizeof(so_reuseaddr));
#ifdef UNIX
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
	setsockopt(rudp->sockfd, SOL_UDP, UDP_SEGMENT, &so_gso, sizeof(so_gso));
	setsockopt(rudp->sockfd, SOL_UDP, UDP_GRO, &so_gro, sizeof(so_gro));
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(rudp->ip);
	addr.sin_port = htons(rudp->port);
	ret = bind(rudp->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		closesocket(rudp->sockfd);
		return kfree(rudp), NULL;
	}

	len = sizeof(addr);
	getsockname(rudp->sockfd, &addr, &len);
	inet_ntop(AF_INET, &addr.sin_addr, rudp->ip, sizeof(rudp->ip));
	rudp->port = ntohs(addr.sin_port);
	rudp->evbase = rudpworker_evbase(rudp->wp);
	rudp->cseq = rudp->sseq = curtime;
	rudp->sesslen = sesslen;
	rudp->sessidle = sessidle * 1000; //ms
	rudp->maxmtu = (maxmtu <= 0) ? RUDP_MAXMTU : maxmtu;
	rudp->interval = (interval <= 0) ? 10 : interval;
	rudp->minrto = (minrto <= 0) ? 10 : minrto;
	rudp->fastresend = (fastresend < 0) ? 0 : fastresend;
	rudp->wndsize = (wndsize <= 0) ? 128 : wndsize;
	rudp->xmitmax = xmitmax * 1000; //ms
	rudp->sndtimeout = sndtimeout * 1000; //ms
	rudp->ntftype = ntftype;
	rudp->recvcb = recvcb;
	rudp->notifycb = notifycb;
	rudp->closecb = closecb;
	rudp->destroycb = destroycb;
	rudp->data = data;
	rudp->htpeer = rudp->htsess = NULL; //hashtable for sessions
	rudpstat_init(&rudp->stat, curtime);
	pthread_mutex_init(&rudp->ht_lck, 0);
	rudp->buffree = NULL;
	rudp->bufusenum = rudp->buffreenum = 0;
	pthread_mutex_init(&rudp->buf_lck, 0);
	rudp->closing = 0;
	rudp->refcnt = 1;

#if WINSOCK_IOCP
	if (rudp_iocp_start(rudp) != 0) {
		pthread_mutex_destroy(&rudp->ht_lck);
		pthread_mutex_destroy(&rudp->buf_lck);
		closesocket(rudp->sockfd);
		return kfree(rudp), NULL;
	}
#else
	event_assign(&rudp->evsock, rudp->evbase, rudp->sockfd, EV_READ | EV_PERSIST, rudpsock_recvcb, rudp);
	event_add(&rudp->evsock, NULL);
#endif

	event_assign(&rudp->chktimer, rudp->evbase, -1, 0, rudpsock_chktimer, rudp);
	event_add(&rudp->chktimer, rudptv_set(tv, RUDPCHK_INTERVAL));
	return rudp;
}

rudpsession_t *rudpsock_connect(rudpsocket_t *rudp, uint32_t saddr, uint16_t port)
{
	struct sockaddr_in peeraddr;
	uint32_t curtime = getcurtime_ms();

	peeraddr.sin_family = AF_INET;
	peeraddr.sin_port = htons(port);
	peeraddr.sin_addr.s_addr = saddr; //inet_addr(ip);
	return rudpsess_get(rudp, (struct sockaddr *)&peeraddr, RUDPCONV_START, curtime, RUDPFLAG_SEND);
}

int rudpsock_sendrate(rudpsocket_t *rudp)
{
	return rudp->stat.sendrate;
}

int rudpsock_recvrate(rudpsocket_t *rudp)
{
	return rudp->stat.recvrate;
}

int rudpsock_failcnt(rudpsocket_t *rudp)
{
	return rudp->stat.failcnt;
}

//return session num of the socket
int rudpsock_sessnum(rudpsocket_t *rudp)
{
	return HASH_CNT(hhsess, rudp->htsess);
}

int rudpbuffer_ref(void *buf)
{
	return _sync_add32(&((rudpbuffer_t *)buf)->refcnt, 1);
}

int rudpbuffer_unref(rudpbuffer_t *buf)
{
	int refcnt = _sync_add32(&buf->refcnt, -1);
	if (refcnt != 1)
		return refcnt;

	rudpsocket_t *rudp = buf->rudpsock;
	if (rudp->buffreenum <= 16) {
		pthread_mutex_lock(&rudp->buf_lck);
		if (rudp->buffreenum <= 16) {
			buf->rudpsess = NULL;
			buf->next = rudp->buffree;
			rudp->buffree = buf;
			rudp->buffreenum++;
			buf = NULL;
		}
		pthread_mutex_unlock(&rudp->buf_lck);
	}
	if (buf != NULL) kfree(buf);
	_sync_add32(&rudp->bufusenum, -1);
	return refcnt;
}

void *rudpbuffer_alloc(rudpsocket_t *rudp, rudpsession_t *session)
{
	rudpbuffer_t *buf = NULL;

	if (rudp->buffree != NULL) {
		pthread_mutex_lock(&rudp->buf_lck);
		if (rudp->buffree != NULL) {
			buf = rudp->buffree;
			buf->refcnt = 1;
			buf->rudpsess = session;
			rudp->buffree = buf->next;
			rudp->buffreenum--;
		}
		pthread_mutex_unlock(&rudp->buf_lck);
	}
	if (buf == NULL) {
		buf = kalloc(sizeof(rudpbuffer_t));
		buf->refcnt = 1;
		buf->rudpsock = rudp;
		buf->rudpsess = session;
	}
	_sync_add32(&rudp->bufusenum, 1);
	return buf;
}

void rudpbuffer_free(void *buf)
{
	rudpbuffer_unref((rudpbuffer_t *)buf);
}
