#ifndef __P2P_SCHED__H
#define __P2P_SCHED__H

#include "btype.h"
#include "p2pmsg.h"
#include "uthash.h"
#include "rudpsock.h"
#include "p2ppeer.h"
#include "p2pcache.h"
#include "p2pm3u8.h"
#include "p2ptcpsrv.h"
#include "ts_stream.h"

typedef struct p2psched_s p2psched_t;

struct p2psched_s
{
	int             refcnt;
	p2pmsg_peer_t   peer;
	uint32_t        reqseq;
	uint32_t        cid;
	p2pcache_t      cache; //TODO: per source
	p2pm3u8_t       m3u8;
	TS_StreamHandle *psh;
	p2ptcpsrv_t    *tcpsrv;
	rudpsocket_t   *p2psock;
	rudpsession_t  *trksess;
	struct event    trktimer;
	p2pblock_t     *reqblk;
	uint64_t        requid;
	p2ppeer_t      *reqtail;
	uint32_t        reqtime;
	uint32_t        rsptime;
	struct event    blktimer;
	struct event    hlotimer;
	int             status;
	p2ppeer_t      *htpeer;  //TODO: no upper->exchange with connected lower
	DLIST_head(p2ppeer_t) ltupper;  //TODO: compre with source seq and choose uppper or lower
	DLIST_head(p2ppeer_t) ltlower;
	pthread_mutex_t ht_lck;
	void           *p2pmgmt;
	UT_hash_handle  hhsched;
};

int p2psched_ref(p2psched_t *sched);
int p2psched_unref(p2psched_t *sched);
p2psched_t *p2psched_new(void *p2pmgmt, uint32_t chid, const char *puship, uint16_t pushport);
void p2psched_destroy(p2psched_t *sched);

#endif
