#ifndef __P2P_TRACKER__H
#define __P2P_TRACKER__H

#include "btype.h"
#include "p2pmsg.h"
#include "uthash.h"
#include "rudpsock.h"
#include "p2ppeer.h"

typedef struct trkpeer_s trkpeer_t;
typedef struct trkchannel_s trkchannel_t;
typedef struct trkpeercfg_s trkpeercfg_t;
typedef struct p2ptrksrv_s p2ptrksrv_t;

struct trkpeer_s
{
	int refcnt;
	p2pmsg_peer_t peer;
	uint64_t upperuid; //upper uid inuse
	uint32_t upperrate; //upper recv rate
	uint64_t startpackid; //cache startpackid
	uint64_t maxpackid; //cache maxpackid
	rudpsession_t *rudpsess;
	DLIST_handle(trkpeer_t) lhpeer;
	UT_hash_handle hhpeer;
	trkchannel_t *channel;
};

struct trkchannel_s
{
	int refcnt;
	uint32_t cid;
	DLIST_head(trkpeer_t) ltpeer;
	DLIST_head(trkpeer_t) ltserver;
	trkpeer_t *htpeer;
	UT_hash_handle hhchannel;
	p2ptrksrv_t *tracker;
	pthread_rwlock_t rwlck;
};

struct trkpeercfg_s
{
	uint64_t uid;
	uint32_t wanip;
	UT_hash_handle hhpeercfg;
};

struct p2ptrksrv_s
{
	int refcnt;
	int exiting;
	uint64_t uidseq;
	p2pmsg_param_t param;
	rudpworker_pool_t *wp;
	rudpsocket_t *rudpsock;
	trkchannel_t *htchannel;
	trkpeercfg_t *htpeercfg;
	SOCKET ifsock;
	pthread_t if_tid;
	pthread_mutex_t ht_lck;
};

int trkpeer_ref(trkpeer_t *peer);
int trkpeer_unref(trkpeer_t *peer);
trkpeer_t *trkpeer_new(trkchannel_t *channel, rudpsession_t *session, p2pmsg_peer_t *msg);
void trkpeer_destroy(trkpeer_t *peer);

int trkchannel_ref(trkchannel_t *channel);
int trkchannel_unref(trkchannel_t *channel);
trkchannel_t *trkchannel_new(p2ptrksrv_t *tracker, uint32_t chid);
trkpeer_t *trkchannel_getpeer(trkchannel_t *channel, rudpsession_t *session, p2pmsg_req_login_t *req, uint32_t curtime);
void trkchannel_destroy(trkchannel_t *channel);

int p2ptrksrv_ref(p2ptrksrv_t *tracker);
int p2ptrksrv_unref(p2ptrksrv_t *tracker);
p2ptrksrv_t *p2ptrksrv_new(const char *cfgfile);
trkchannel_t *p2ptrksrv_getchannel(p2ptrksrv_t *tracker, uint32_t chid);
void p2ptrksrv_destroy(p2ptrksrv_t *tracker);

#endif
