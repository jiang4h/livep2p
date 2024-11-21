#include "app_log.h"
#include "p2ppeer.h"
#include "rudpsock.h"
#include "p2psched.h"

int p2ppeer_ref(p2ppeer_t *peer)
{
	return _sync_add32(&peer->refcnt, 1);
}

int p2ppeer_unref(p2ppeer_t *peer)
{
	int refcnt = _sync_add32(&peer->refcnt, -1);
	if (refcnt == 1) {
		log_debug("p2ppeer freed: %p", peer);
		pthread_mutex_destroy(&peer->lck);
		p2psched_unref(peer->p2psched);
		kfree(peer);
	}
	return refcnt;
}

p2ppeer_t *p2ppeer_new(void *sched, p2pmsg_peer_t *msg, int upper)
{
	assert(msg);
	p2ppeer_t *peer = (p2ppeer_t *)kcalloc(1, sizeof(p2ppeer_t));

	p2psched_ref(sched);
	peer->refcnt = 1;
	peer->p2psched = sched;
	memcpy(&peer->peer, msg, sizeof(peer->peer));
	peer->upper = upper;
	peer->usesess = NULL;
	peer->wansess = peer->lansess = NULL;
	pthread_mutex_init(&peer->lck, 0);
	return peer;
}

void p2ppeer_setwansess(p2ppeer_t *peer, rudpsession_t *rudpsess)
{
	rudpsession_t *oldsess = NULL;

	if (rudpsess != NULL)
		*(uint64_t *)rudpsess->data = peer->peer.uid;

	pthread_mutex_lock(&peer->lck);
	if (peer->wansess != rudpsess) {
		oldsess = peer->wansess;
		if (oldsess != NULL && peer->usesess == oldsess) { //ref by usesess
			rudpsess_unref(oldsess);
			oldsess = NULL;
		}
		if (rudpsess != NULL) rudpsess_ref(rudpsess);
		peer->wansess = rudpsess;
	}
	pthread_mutex_unlock(&peer->lck);

	if (oldsess != NULL) {
		*(uint64_t *)oldsess->data = 0;
		rudpsess_close(oldsess, 1);
	}
}

rudpsession_t *p2ppeer_getwansess(p2ppeer_t *peer)
{
	rudpsession_t *rudpsess;

	pthread_mutex_lock(&peer->lck);
	rudpsess = peer->wansess;
	if (rudpsess != NULL)
		rudpsess_ref(rudpsess);
	pthread_mutex_unlock(&peer->lck);
	return rudpsess;
}

void p2ppeer_setlansess(p2ppeer_t *peer, rudpsession_t *rudpsess)
{
	rudpsession_t *oldsess = NULL;

	if (rudpsess != NULL)
		*(uint64_t *)rudpsess->data = peer->peer.uid;

	pthread_mutex_lock(&peer->lck);
	if (peer->lansess != rudpsess) {
		oldsess = peer->lansess;
		if (oldsess != NULL && peer->usesess == oldsess) {
			rudpsess_unref(oldsess);
			oldsess = NULL;
		}
		if (rudpsess != NULL) rudpsess_ref(rudpsess);
		peer->lansess = rudpsess;
	}
	pthread_mutex_unlock(&peer->lck);

	if (oldsess != NULL) {
		*(uint64_t *)oldsess->data = 0;
		rudpsess_close(oldsess, 1);
	}
}

rudpsession_t *p2ppeer_getlansess(p2ppeer_t *peer)
{
	rudpsession_t *rudpsess;

	pthread_mutex_lock(&peer->lck);
	rudpsess = peer->lansess;
	if (rudpsess != NULL)
		rudpsess_ref(rudpsess);
	pthread_mutex_unlock(&peer->lck);
	return rudpsess;
}

void p2ppeer_setusesess(p2ppeer_t *peer, rudpsession_t *rudpsess)
{
	if (rudpsess != NULL)
		*(uint64_t *)rudpsess->data = peer->peer.uid;
	
	pthread_mutex_lock(&peer->lck);
	if (peer->usesess == rudpsess) {
		pthread_mutex_unlock(&peer->lck);
		return;
	}

	rudpsession_t *oldwansess = NULL;
	rudpsession_t *oldlansess = NULL;
	rudpsession_t *oldusesess = NULL;

	oldusesess = peer->usesess;
	if (rudpsess != NULL) rudpsess_ref(rudpsess);
	peer->usesess = rudpsess;

	if (rudpsess != NULL) {
		if (rudpsess != peer->wansess)
			oldwansess = peer->wansess;
		else 
			rudpsess_unref(peer->wansess);
		peer->wansess = NULL;

		if (rudpsess != peer->lansess)
			oldlansess = peer->lansess;
		else 
			rudpsess_unref(peer->lansess);
		peer->lansess = NULL;
	}
	pthread_mutex_unlock(&peer->lck);

	if (oldwansess != NULL) {
		*(uint64_t *)oldwansess->data = 0;
		rudpsess_close(oldwansess, 1);
	}
	if (oldlansess != NULL) {
		*(uint64_t *)oldlansess->data = 0;
		rudpsess_close(oldlansess, 1);
	}
	if (oldusesess != NULL) {
		*(uint64_t *)oldusesess->data = 0;
		rudpsess_close(oldusesess, 1);
	}
}

rudpsession_t *p2ppeer_getusesess(p2ppeer_t *peer)
{
	rudpsession_t *rudpsess;

	pthread_mutex_lock(&peer->lck);
	rudpsess = peer->usesess;
	if (rudpsess != NULL)
		rudpsess_ref(rudpsess);
	pthread_mutex_unlock(&peer->lck);
	return rudpsess;
}

void p2ppeer_closesess(p2ppeer_t *peer, rudpsession_t *rudpsess)
{
	if (rudpsess == NULL) return;

	rudpsession_t *oldwansess = NULL;
	rudpsession_t *oldlansess = NULL;
	rudpsession_t *oldusesess = NULL;

	pthread_mutex_lock(&peer->lck);
	if (rudpsess == peer->wansess) {
		if (rudpsess == peer->usesess)
			rudpsess_unref(peer->wansess);
		else
			oldwansess = peer->wansess;
		peer->wansess = NULL;
	}

	if (rudpsess == peer->lansess) {
		if (rudpsess == peer->usesess)
			rudpsess_unref(peer->lansess);
		else
			oldlansess = peer->lansess;
		peer->lansess = NULL;
	}
	
	if (rudpsess == peer->usesess) {
		oldusesess = peer->usesess;
		peer->usesess = NULL;
	}
	pthread_mutex_unlock(&peer->lck);

	if (oldwansess != NULL) {
		*(uint64_t *)oldwansess->data = 0;
		rudpsess_close(oldwansess, 1);
	}
	if (oldlansess != NULL) {
		*(uint64_t *)oldlansess->data = 0;
		rudpsess_close(oldlansess, 1);
	}
	if (oldusesess != NULL) {
		*(uint64_t *)oldusesess->data = 0;
		rudpsess_close(oldusesess, 1);
	}
}

void p2ppeer_destroy(p2ppeer_t *peer)
{
	p2ppeer_setwansess(peer, NULL);
	p2ppeer_setlansess(peer, NULL);
	p2ppeer_setusesess(peer, NULL);
	p2pblock_destroy(&peer->waitblk);
	p2ppeer_unref(peer);
}

int p2ppeer_inuse(p2ppeer_t *peer)
{
	if (!peer->upper) {
		if (peer->waiting != 0 && peer->waiting != -1)
			return 1;
		pthread_mutex_lock(&peer->lck);
		if (peer->usesess && peer->usesess->kcp->nsnd_buf) {
			pthread_mutex_unlock(&peer->lck);
			return 1;
		}
		pthread_mutex_unlock(&peer->lck);
	}
	return 0;
}

uint32_t p2ppeer_recvrate(p2ppeer_t *peer)
{
	int recvrate = 0;
	pthread_mutex_lock(&peer->lck);
	if (peer->usesess)
		recvrate = rudpsess_recvrate(peer->usesess);
	pthread_mutex_unlock(&peer->lck);
	return recvrate;
}

uint32_t p2ppeer_sendrate(p2ppeer_t *peer)
{
	int sendrate = 0;
	pthread_mutex_lock(&peer->lck);
	if (peer->usesess)
		sendrate = rudpsess_sendrate(peer->usesess);
	pthread_mutex_unlock(&peer->lck);
	return sendrate;
}