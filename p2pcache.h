#ifndef _P2P_CACHE_H
#define _P2P_CACHE_H

#include "btype.h"
#include "p2pmsg.h"
#include "p2pblock.h"

typedef struct p2pcache_s p2pcache_t;
typedef int fn_cachecb(p2pcache_t *cache, uint64_t packid);

struct p2pcache_s
{
	uint16_t        packsize;       //byte num of a pack
	uint32_t        packnum;        //pack num of buf
	uint32_t        blocksize;      //pack num of a block
	uint16_t        blocknum;       //block num of buf
	uint16_t        packskip;       //pack num between read and write  
	p2pmsg_pack_t  *packs;
	p2pblock_t     *blocks;
	uint64_t        startpackid;
	uint64_t        maxpackid;
	pthread_rwlock_t rwlck;
	fn_cachecb     *cachecb;
	void           *p2psched;
};

#define p2pcache_allocbuffer(_buf, rudpsock, rudpsess) (_buf = (char*)rudpbuffer_alloc(rudpsock, rudpsess), _buf = (_buf) ? (char*)(_buf) + offsetof(p2pmsg_pack_t, data) : NULL)
#define p2pcache_refbuffer(_buf) rudpbuffer_ref((char*)(_buf) - offsetof(p2pmsg_pack_t, data))
#define p2pcache_freebuffer(_buf) rudpbuffer_free((char*)(_buf) - offsetof(p2pmsg_pack_t, data))

int	p2pcache_init(p2pcache_t *cache, p2pmsg_param_t *param, fn_cachecb *cachecb, void *p2psched);
uint64_t p2pcache_findkeypack(p2pcache_t *cache);
int p2pcache_outdated(p2pcache_t *cache, uint64_t packid);
int p2pcache_read(p2pcache_t *cache, uint64_t packid, p2pmsg_pack_t*pack);
p2pblock_t *p2pcache_write(p2pcache_t *cache, p2pmsg_pack_t *pack);
p2pblock_t *p2pcache_nextblk(p2pcache_t *cache, p2pblock_t *curblk);
p2pblock_t *p2pcache_findblk(p2pcache_t *cache, uint64_t packid);
void p2pcache_destroy(p2pcache_t *cache);

#endif

