#include "p2pblock.h"

uint8_t p2pbitmap_get(p2pmsg_bitmap_t *bm, uint16_t bitpos)
{
	assert(bm);
	assert(bm->bits);

	if (bitpos >= bm->bitsize)
		return 0;
	return bm->bits[BITS_POS(bitpos)] & BITS_MASK(bitpos);
}

uint8_t p2pbitmap_set(p2pmsg_bitmap_t *bm, uint16_t bitpos, uint8_t fill)
{
	uint16_t pos = BITS_POS(bitpos);
	uint8_t  mask = BITS_MASK(bitpos);
	uint8_t oldval;

	assert(bm);
	assert(bm->bits);

	if (bitpos >= bm->bitsize)
		return 0;

	oldval = fill ? 
		_sync_or8(&bm->bits[pos], mask) : 
		_sync_and8(&bm->bits[pos], ~mask);
	return oldval & mask;
}

int p2pbitmap_count(p2pmsg_bitmap_t *bm)
{
	assert(bm);
	assert(bm->bits);

	static char _BitsPerHex[] = "\0\1\1\2\1\2\2\3\1\2\2\3\2\3\3\4";
	int bitcount = 0;
	uint16_t len = BITS_LEN(bm->bitsize), pos;
	uint8_t val8 = 0;

	for (pos = 0; pos < len; pos++)
	{
		for (val8 = bm->bits[pos]; val8 != 0; val8 >>= 4)
			bitcount += _BitsPerHex[val8 & 0xF];
	}
	return bitcount;
}

void p2pblock_init(p2pblock_t *blk, uint16_t bitsize, uint64_t packid)
{
	uint64_t startpackid = packid / bitsize * bitsize;

	if (bitsize <= 8 * sizeof(blk->bits))
		blk->bm.bits = blk->bits;
	else
		blk->bm.bits = (uint8_t *)kzalloc(BITS_LEN(bitsize));
	blk->bm.bitstart = packid - startpackid;
	blk->bm.bitsize = bitsize;
	blk->bm.startpackid = startpackid;
	blk->fillcount = 0;
}

void p2pblock_reset(p2pblock_t *blk, uint64_t packid)
{
	uint64_t startpackid = p2pblock_startpackid(packid, blk->bm.bitsize);

	memset(blk->bm.bits, 0, BITS_LEN(blk->bm.bitsize));
	blk->bm.bitstart = packid - startpackid;
	blk->bm.startpackid = startpackid;
	blk->fillcount = 0;
}

void p2pblock_setbm(p2pblock_t *blk, p2pmsg_bitmap_t *bm, int bitstart)
{
	int len = BITS_LEN(bm->bitsize);

	blk->bm.bitstart = (bitstart >= 0 && bitstart < bm->bitsize) ? (uint16_t)bitstart : bm->bitstart;
	blk->bm.bitsize = bm->bitsize;
	blk->bm.startpackid = bm->startpackid;
	if (len <= sizeof(blk->bits))
		blk->bm.bits = blk->bits;
	else
		blk->bm.bits = (uint8_t *)kzalloc(len);
	memcpy(blk->bm.bits, bm->bits, len);
	blk->fillcount = p2pbitmap_count(bm);
}

int p2pblock_isfull(p2pblock_t *blk)
{
	return (blk->bm.bitstart + blk->fillcount +
		(((int64_t)(blk->bm.startpackid + blk->bm.bitstart) <= 0 && //ignore packid 0
			(int64_t)(blk->bm.startpackid + blk->bm.bitsize) > 0) ? 1 : 0)) >= blk->bm.bitsize ? 1 : 0;
}

int p2pblock_setbit(p2pblock_t *blk, uint64_t packid, int cmdtype)
{
	uint64_t startpackid = packid / blk->bm.bitsize * blk->bm.bitsize;
	int fill;

	if (blk->bm.startpackid == 0)
		blk->bm.startpackid = startpackid;
	else if (blk->bm.startpackid != startpackid) {
		blk->bm.startpackid = startpackid;
		blk->bm.bitstart = 0;
		blk->fillcount = 0;
		memset(blk->bm.bits, 0, BITS_LEN(blk->bm.bitsize));
	}

	if (cmdtype == P2P_CMD_ACK_PACK_ANY)
		blk->bm.bitstart = packid - startpackid;
	fill = p2pbitmap_set(&blk->bm, (uint16_t)(packid - startpackid), 1);
	if (!fill) _sync_add32(&blk->fillcount, 1);
	return fill;
}

int p2pblock_contains(p2pblock_t *blk, uint64_t packid)
{
	if (blk->bm.startpackid == packid / blk->bm.bitsize * blk->bm.bitsize)
		return 1;
	return 0;
}

void p2pblock_destroy(p2pblock_t *blk)
{
	assert(blk);

	if (blk->bm.bitsize > 8 * sizeof(blk->bits) && blk->bm.bits != NULL) 
		kfree(blk->bm.bits);
}
