#include "p2pcache.h"
#include "p2psched.h"
#include "rudpsock.h"
#include "app_log.h"

int	p2pcache_init(p2pcache_t *cache, p2pmsg_param_t *param, fn_cachecb *cachecb, void *p2psched)
{
	uint32_t i;

	assert(cache);
	assert(param);

	pthread_rwlock_init(&cache->rwlck, 0);
	cache->packsize = param->packsize;
	cache->blocksize = param->blocksize;
	cache->blocknum = param->blocknum;
	cache->packskip = param->packskip;
	cache->packnum = param->blocksize * param->blocknum;
	cache->packs = kcalloc(cache->packnum, sizeof(p2pmsg_pack_t));
	for (i = 0; i < cache->packnum; i++) {
		memset(&cache->packs[i], 0, sizeof(p2pmsg_pack_t));
	}
	cache->blocks = (p2pblock_t *)kcalloc(cache->blocknum, sizeof(p2pblock_t));
	for (i = 0; i < cache->blocknum; i++) {
		p2pblock_init(&cache->blocks[i], cache->blocksize, 0);
	}
	cache->startpackid = cache->maxpackid = 0;
	cache->cachecb = cachecb;
	cache->p2psched = p2psched;
	return 0;
}

uint64_t p2pcache_findkeypack(p2pcache_t *cache)
{
	uint64_t packid = cache->startpackid;
	p2pmsg_pack_t *pack;
	int i;

	if (packid == 0)
		return 0;
	
	for (; (int64_t)(cache->maxpackid - packid) >= 0; packid++) {
		i = packid % cache->packnum;
		pthread_rdlock_lock(&cache->rwlck);
		pack = &cache->packs[i];
		if (pack->packid == 0) {
			if (cache->startpackid == packid)
				cache->startpackid++;
			pthread_rdlock_unlock(&cache->rwlck);
			continue;
		}
		if (pack->packid != packid) {
			pthread_rdlock_unlock(&cache->rwlck);
			return 0;
		}
		if (pack->attr != 0) {
			pthread_rdlock_unlock(&cache->rwlck);
			return packid;
		}
		pthread_rdlock_unlock(&cache->rwlck);
	}
	return 0;
}

int p2pcache_outdated(p2pcache_t *cache, uint64_t packid)
{
	return ((int64_t)(packid - cache->startpackid) < 0 || 
			(int64_t)(packid - cache->maxpackid) > cache->packnum) ? 1 : 0;
}

int p2pcache_read(p2pcache_t *cache, uint64_t packid, p2pmsg_pack_t *pack)
{
	assert(cache);
	assert(cache->packnum);
	assert(cache->packs);

	int i = packid % cache->packnum;

	pthread_rdlock_lock(&cache->rwlck);
	if (packid == 0 || cache->packs[i].packid != packid) {
		pthread_rdlock_unlock(&cache->rwlck);
		return -1;
	}
	memcpy(pack, &cache->packs[i], sizeof(p2pmsg_pack_t));
	p2pcache_refbuffer(pack->data);
	pthread_rdlock_unlock(&cache->rwlck);
	return i;
}

p2pblock_t *p2pcache_write(p2pcache_t *cache, p2pmsg_pack_t *pack)
{
	assert(cache);
	assert(pack);
	assert(pack->data);

	int ipack, iblk, fill, isfull, attr;
	p2pmsg_pack_t *curpack;
	p2pblock_t *curblk;
	uint8_t *oldbuf;
	p2psched_t *sched;

	ipack = pack->packid % cache->packnum;
	iblk = ipack / cache->blocksize;

	pthread_wrlock_lock(&cache->rwlck);
	curpack = &cache->packs[ipack];
	curblk = &cache->blocks[iblk];

	oldbuf = curpack->data;
	memcpy(curpack, pack, sizeof(p2pmsg_pack_t));
	if (oldbuf != NULL)
		p2pcache_freebuffer(oldbuf);

	if (cache->startpackid == 0)
		cache->startpackid = pack->packid;
	if ((int64_t)(cache->maxpackid - pack->packid) < 0)
		cache->maxpackid = pack->packid;
	if ((int64_t)(cache->maxpackid - cache->startpackid) > cache->packnum - cache->packskip)
		cache->startpackid = cache->maxpackid - (cache->packnum - cache->packskip);
	pthread_wrlock_unlock(&cache->rwlck);

	fill = p2pblock_setbit(curblk, pack->packid, pack->cmd.type);
	if (!fill) {
		sched = (p2psched_t *)cache->p2psched;
		attr = ts_is_keyframe(sched->psh, pack->data, pack->len);
		p2pm3u8_add(&sched->m3u8, pack->packid, pack->len,
			attr, ts_get_pts(sched->psh), cache->startpackid);
		isfull = p2pblock_isfull(curblk);
		if (isfull) {
			log_debug("cid:%d packid=%llu key=%d startpackid=%llu maxpackid=%llu ipack=%d iblk=%d isfull=%d %d",
				((p2psched_t *)cache->p2psched)->cid, pack->packid, pack->attr, cache->startpackid, cache->maxpackid, ipack, iblk, isfull, fill);
		}
		cache->cachecb(cache, pack->packid);
	}
	else {
		log_debug("cid:%d duplicate packid=%llu key=%d startpackid=%llu maxpackid=%llu ipack=%d iblk=%d",
			((p2psched_t *)cache->p2psched)->cid, pack->packid, pack->attr, cache->startpackid, cache->maxpackid, ipack, iblk);
	}
	return curblk;
}

p2pblock_t *p2pcache_nextblk(p2pcache_t *cache, p2pblock_t *curblk)
{
	int iblk = curblk - cache->blocks;
	p2pblock_t *nextblk = &cache->blocks[(iblk + 1) % cache->blocknum];
	uint64_t nextpackid = curblk->bm.startpackid + curblk->bm.bitsize;

	if (nextblk->bm.startpackid != nextpackid) {
		p2pblock_reset(nextblk, nextpackid);
	}
	return nextblk;
}

p2pblock_t *p2pcache_findblk(p2pcache_t *cache, uint64_t packid)
{
	int iblk = (packid % cache->packnum) / cache->blocksize;
	p2pblock_t *curblk = &cache->blocks[iblk];

	if (p2pblock_contains(curblk, packid)) return curblk;
	else return NULL;
}

void p2pcache_destroy(p2pcache_t *cache)
{
	uint32_t i;

	if (cache->packs) {
		for (i = 0; i < cache->packnum; i++) {
			if (cache->packs[i].data != NULL)
				p2pcache_freebuffer(cache->packs[i].data);
		}
		kfree(cache->packs);
		cache->packs = NULL;
	}
	if (cache->blocks) {
		kfree(cache->blocks);
		cache->blocks = NULL;
	}
	pthread_rwlock_destroy(&cache->rwlck);
}
