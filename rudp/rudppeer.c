#include "rudppeer.h"
#include "rudpsock.h"
#include "app_log.h"

int rudppeer_ref(rudppeer_t *peer)
{
	return _sync_add32(&peer->refcnt, 1);
}

int rudppeer_unref(rudppeer_t *peer)
{
	int refcnt = _sync_add32(&peer->refcnt, -1);
	if (refcnt != 1)
		return refcnt;
	
	log_debug("peer freed! %p\n", peer);
	if (peer->sockfd != INVALID_SOCKET) {
		event_del(&peer->evsock);
		closesocket(peer->sockfd);
	}
	kfree(peer);
	return refcnt;
}

static void rudppeer_recvcb(evutil_socket_t fd, short event, void *arg)
{
	rudppeer_t *peer = (rudppeer_t *)arg;
	rudpsocket_t *rudp = peer->rudpsock;
	rudpsession_t *session, *sessnext;
	rudpbuffer_t *rcvbuf = rudpbuffer_alloc(rudp, NULL);
	socklen_t addrlen = sizeof(struct sockaddr);
	uint32_t peerconv;
	int closing;

	assert((uintptr_t)rcvbuf > 0x10000);
	rcvbuf->len = recvfrom(fd, rcvbuf->buf, sizeof(rcvbuf->buf), 0, &rcvbuf->addr, &addrlen);
	if (rcvbuf->len <= 0) {
		rudpbuffer_free(rcvbuf);
		return;
	}

	//log_debug("rudp:%p buf:%p len:%d", rudp, rcvbuf, rcvbuf->len);
	peerconv = ikcp_getconv(rcvbuf->buf);
	closing = rudp->closing ? 1 : ikcp_chkrst(rcvbuf->buf);
	if (closing == 0 && !memcmp(&peer->addr, &rcvbuf->addr, RUDPKEY_ADDRLEN)) {
		pthread_mutex_lock(&peer->lt_lck);
		DLIST_FOREACH(lhsess, peer->ltsess, session, sessnext) {
			if (session->peersessid == CONV_MYSESSID(peerconv)) {
				rudpsess_ref(session);
				rcvbuf->rudpsess = session;
				break;
			}
		}
		pthread_mutex_unlock(&peer->lt_lck);
	}

	rudpsock_ref(rcvbuf->rudpsock);
	rudpsock_recvjob1(rcvbuf);// rudpworker_addjob(rudp->wp, rudpsock_recvjob1, rcvbuf, 1);
}

rudppeer_t *rudppeer_get(void *rudpsock, struct sockaddr *peeraddr, uint32_t curtime, int flag)
{
	rudpsocket_t *rudp = (rudpsocket_t *)rudpsock;
	rudppeer_t *peer;

	pthread_mutex_lock(&rudp->ht_lck);
	HASH_FIND(hhpeer, rudp->htpeer, peeraddr, RUDPKEY_ADDRLEN, peer);
	if (peer != NULL) {
		rudppeer_ref(peer);
		pthread_mutex_unlock(&rudp->ht_lck);
		return peer;
	}
	if (flag == RUDPFLAG_CLOSE) {
		pthread_mutex_unlock(&rudp->ht_lck);
		return NULL;
	}
	peer = (rudppeer_t *)kcalloc(1, sizeof(rudppeer_t));
	peer->addr = *peeraddr;
	peer->evbase = rudpworker_evbase(rudp->wp);
	peer->sockfd = INVALID_SOCKET;
	DLIST_INIT(peer->ltsess);
	peer->refcnt = 2;  //1 + 1:rudp->htpeer
	peer->rudpsock = rudp;
	pthread_mutex_init(&peer->lt_lck, 0);
	HASH_ADD(hhpeer, rudp->htpeer, addr, RUDPKEY_ADDRLEN, peer);
	pthread_mutex_unlock(&rudp->ht_lck);

	struct sockaddr_in addr;
	SOCKET sockfd;
	int so_sndbuf = rudp->wndsize * 1500;
	int so_rcvbuf = rudp->wndsize * 1500;
	int so_reuseaddr = 1;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == INVALID_SOCKET)
		return peer;

	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &so_sndbuf, sizeof(so_sndbuf));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(so_rcvbuf));
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&so_reuseaddr, sizeof(so_reuseaddr));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(rudp->ip);
	addr.sin_port = htons(rudp->port);
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		closesocket(sockfd);
		return peer;
	}
		
	if (connect(sockfd, &peer->addr, sizeof(peer->addr)) < 0) {
		closesocket(sockfd);
		return peer;
	}

	peer->evbase = rudpworker_evbase(rudp->wp);

#if WINSOCK_IOCP
	if (rudp_iocp_add(peer) != 0) {
		closesocket(sockfd);
		return peer;
	}
#else
	event_assign(&peer->evsock, peer->evbase, sockfd, EV_READ | EV_PERSIST, rudppeer_recvcb, peer);
	event_add(&peer->evsock, NULL);
#endif

	peer->sockfd = sockfd;
	return peer;
}
