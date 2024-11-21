#ifndef _RUDPPEER_H
#define _RUDPPEER_H

#include "btype.h"
#include "uthash.h"
#include "rudpstat.h"
#include "rudpsess.h"

typedef struct rudppeer_s rudppeer_t;

struct rudppeer_s
{
	uint32_t refcnt;
	struct event_base *evbase;
	SOCKET sockfd;
	struct event evsock;
	struct sockaddr addr;
	void *rudpsock;
	UT_hash_handle hhpeer;
	DLIST_head(rudpsession_t) ltsess;
	pthread_mutex_t lt_lck;
};

int rudppeer_ref(rudppeer_t *peer);
int rudppeer_unref(rudppeer_t *peer);
rudppeer_t *rudppeer_get(void *rudpsock, struct sockaddr *peeraddr, uint32_t curtime, int flag);

#endif