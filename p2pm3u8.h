#ifndef _P2P_M3U8_H
#define _P2P_M3U8_H

#include "btype.h"
#include "p2pmsg.h"

typedef struct p2pm3u8_seg_s p2pm3u8_seg_t;
typedef struct p2pm3u8_s p2pm3u8_t;

struct p2pm3u8_seg_s
{
	uint64_t firstpackid;
	uint64_t firstpts;
	int64_t lastpackid;
	int64_t lastpts;
	int size;
	uint64_t seq;
	uint64_t ts;
	DLIST_handle(p2pm3u8_seg_t) lh;
};

struct p2pm3u8_s
{
	p2pm3u8_seg_t *cur;
	DLIST_head(p2pm3u8_seg_t) lt;
	uint64_t seq;
	pthread_mutex_t lck;
	void *p2psched;
};

#define p2pm3u8_dur_us(seg) ((int64_t)((seg)->lastpts - (seg)->firstpts) * 100 / 9)

int p2pm3u8_init(p2pm3u8_t *m3u8, void *p2psched);
int p2pm3u8_destroy(p2pm3u8_t *m3u8);

int p2pm3u8_add(p2pm3u8_t *m3u8, uint64_t packid,
	int size, int bkey, uint64_t pts, uint64_t startpackid);

char* p2pm3u8_text(p2pm3u8_t *m3u8, int *plen, const char *auth);

#endif