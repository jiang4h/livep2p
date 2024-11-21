#ifndef _P2P_BLOCK_H
#define _P2P_BLOCK_H

#include "btype.h"
#include "p2pmsg.h"

#define p2pblock_startpackid(packid,bitsize)  ((packid) / (bitsize) * (bitsize))

typedef struct p2pblock_s p2pblock_t;

struct p2pblock_s
{
	p2pmsg_bitmap_t bm;
	int fillcount;
	uint8_t bits[64];
};

uint8_t p2pbitmap_get(p2pmsg_bitmap_t *bm, uint16_t bitpos);
uint8_t p2pbitmap_set(p2pmsg_bitmap_t *bm, uint16_t bitpos, uint8_t fill);
int p2pbitmap_count(p2pmsg_bitmap_t *bm);

void p2pblock_init(p2pblock_t *blk, uint16_t bitsize, uint64_t packid);
void p2pblock_reset(p2pblock_t *blk, uint64_t packid);
void p2pblock_setbm(p2pblock_t *blk, p2pmsg_bitmap_t *bm, int bitstart);
int p2pblock_isfull(p2pblock_t *blk);
int p2pblock_setbit(p2pblock_t *blk, uint64_t packid, int cmdtype);
int p2pblock_contains(p2pblock_t *blk, uint64_t packid);
void p2pblock_destroy(p2pblock_t *blk);

#endif
