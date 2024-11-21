#ifndef __P2P_PEER__H
#define __P2P_PEER__H

#include "btype.h"
#include "p2pmsg.h"
#include "uthash.h"
#include "rudpsess.h"
#include "p2pblock.h"

typedef struct p2ppeer_s    p2ppeer_t;

struct p2ppeer_s
{
	int             refcnt;
	void           *p2psched;
	p2pmsg_peer_t   peer;
	int             upper;
	uint32_t        waiting;
	p2pmsg_cmd_t    waitreq;
	p2pblock_t      waitblk;
	rudpsession_t  *usesess;
	rudpsession_t  *wansess, *lansess;
	pthread_mutex_t lck;
	UT_hash_handle  hhpeer;
	DLIST_handle(p2ppeer_t) lhpeer;
};

#define p2ppeer_upper(cmdtype)   IS_CMD_ACK(cmdtype)

int p2ppeer_ref(p2ppeer_t *peer);
int p2ppeer_unref(p2ppeer_t *peer);
p2ppeer_t *p2ppeer_new(void *sched, p2pmsg_peer_t *msg, int upper);
void p2ppeer_destroy(p2ppeer_t *peer);

void p2ppeer_setwansess(p2ppeer_t *peer, rudpsession_t *rudpsess);
void p2ppeer_setlansess(p2ppeer_t *peer, rudpsession_t *rudpsess);
void p2ppeer_setusesess(p2ppeer_t *peer, rudpsession_t *rudpsess);
rudpsession_t *p2ppeer_getwansess(p2ppeer_t *peer);
rudpsession_t *p2ppeer_getlansess(p2ppeer_t *peer);
rudpsession_t *p2ppeer_getusesess(p2ppeer_t *peer);
void p2ppeer_closesess(p2ppeer_t *peer, rudpsession_t *rudpsess);

int p2ppeer_inuse(p2ppeer_t *peer);
uint32_t p2ppeer_recvrate(p2ppeer_t *peer);
uint32_t p2ppeer_sendrate(p2ppeer_t *peer);

#endif
