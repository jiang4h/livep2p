#include "p2pm3u8.h"
#include "p2psched.h"
#include "app_log.h"

int p2pm3u8_init(p2pm3u8_t *m3u8, void *p2psched)
{
	m3u8->cur = NULL;
	DLIST_INIT(m3u8->lt);
	m3u8->seq = 0;
	pthread_mutex_init(&m3u8->lck, NULL);
	m3u8->p2psched = p2psched;
	return 0;
}

int p2pm3u8_destroy(p2pm3u8_t *m3u8)
{
	p2pm3u8_seg_t *seg, *segnext;

	pthread_mutex_lock(&m3u8->lck);
	DLIST_FOREACH(lh, m3u8->lt, seg, segnext)
	{
		DLIST_DEL(lh, m3u8->lt, seg);
		kfree(seg);
	}
	pthread_mutex_unlock(&m3u8->lck);
	pthread_mutex_destroy(&m3u8->lck);
	return 0;
}

int p2pm3u8_add(p2pm3u8_t *m3u8, uint64_t packid,
	int size, int bkey, uint64_t pts, uint64_t startpackid)
{
	uint64_t curtime = getcurtime_us();
	p2pm3u8_seg_t *seg, *segnext;
	int i;

	pthread_mutex_lock(&m3u8->lck);
	if (bkey && m3u8->cur && m3u8->cur->lastpackid)
	{
		m3u8->cur->lastpts = pts;
		if (p2pm3u8_dur_us(m3u8->cur) > 3000000LL)
		{
			DLIST_ADD_TAIL(lh, m3u8->lt, m3u8->cur);
			m3u8->cur = NULL;
		}
	}

	seg = DLIST_HEAD(m3u8->lt);
	if (seg && seg->firstpackid < startpackid)
	{
		DLIST_FOREACH(lh, m3u8->lt, seg, segnext)
		{
			if (seg->firstpackid >= startpackid)
				break;
			log_debug("m3u8 remove seq:%llu b:%llu, %llu", seg->seq, seg->firstpackid, startpackid);
			DLIST_DEL(lh, m3u8->lt, seg);
			kfree(seg);
		}
		for (seg = DLIST_HEAD(m3u8->lt), i = 0; seg && i < 5; seg = DLIST_NEXT(lh, seg), i++);
		if (!seg) seg = DLIST_TAIL(m3u8->lt);
		if (seg && seg->ts > curtime)
		{
			seg->ts = curtime;
			for (segnext = DLIST_PREV(lh, seg); segnext; segnext = DLIST_PREV(lh, segnext))
			{
				segnext->ts = DLIST_NEXT(lh, segnext)->ts - p2pm3u8_dur_us(segnext);
			}
			for (segnext = DLIST_NEXT(lh, seg); segnext; segnext = DLIST_NEXT(lh, segnext))
			{
				segnext->ts = DLIST_PREV(lh, segnext)->ts + p2pm3u8_dur_us(DLIST_PREV(lh, segnext));
			}
		}
	}

	if (!m3u8->cur)
	{
		if (!bkey)
		{
			pthread_mutex_unlock(&m3u8->lck);
			return 0;
		}
		m3u8->cur = kcalloc(1, sizeof(p2pm3u8_seg_t));
		m3u8->cur->firstpackid = packid;
		m3u8->cur->firstpts = pts;
		m3u8->cur->size = size;
		m3u8->cur->seq = m3u8->seq;
		m3u8->seq++;
		seg = DLIST_TAIL(m3u8->lt);
		m3u8->cur->ts = seg ? (seg->ts + p2pm3u8_dur_us(seg)) : curtime;
	}
	else
	{
		m3u8->cur->lastpackid = packid;
		m3u8->cur->size += size;
	}
	pthread_mutex_unlock(&m3u8->lck);
	return 0;
}

//#EXTM3U
//#EXT-X-TARGETDURATION:10
//#EXT-X-VERSION:3
//#EXT-X-MEDIA-SEQUENCE:0
//#EXTINF:10,
//seg?cid=<cid>&b=<firstpackid>&e=<lastpackid>&n=<size>&auth=<auth>
//#EXTINF:10,
//seg?cid=<cid>&b=<firstpackid>&e=<lastpackid>&n=<size>&auth=<auth>
//#EXTINF:10,
//seg?cid=<cid>&b=<firstpackid>&e=<lastpackid>&n=<size>&auth=<auth>

char *p2pm3u8_text(p2pm3u8_t *m3u8, int *plen, const char *auth)
{
	p2psched_t *sched = (p2psched_t *)m3u8->p2psched;
	p2pm3u8_seg_t *seg;
	char *buf;
	size_t size, len, n;
	int maxdur, i;
	uint64_t curtime;

	if (DLIST_COUNT(m3u8->lt) <= 0)
		return NULL;

	curtime = getcurtime_us();
	pthread_mutex_lock(&m3u8->lck);
	seg = DLIST_HEAD(m3u8->lt);
	if (!seg)
	{
		pthread_mutex_unlock(&m3u8->lck);
		return NULL;
	}
	while (seg && seg->ts < curtime) seg = DLIST_NEXT(lh, seg);
	if (!seg) seg = DLIST_TAIL(m3u8->lt);
	maxdur = 3;
	size = 99;
	i = 0;
	while (seg)
	{
		int dur = (p2pm3u8_dur_us(seg) + 999999) / 1000000;
		if (maxdur < dur)
			maxdur = dur;
		size += 144;
		i++;
		if (i >= 10)
			break;
		seg = DLIST_PREV(lh, seg);
	}
	if (!seg) seg = DLIST_HEAD(m3u8->lt);
	buf = kalloc(size + 1);
	len = snprintf(buf, size, "#EXTM3U\n#EXT-X-TARGETDURATION:%d\n#EXT-X-VERSION:3\n#EXT-X-MEDIA-SEQUENCE:%llu\n", maxdur, seg->seq);
	while (seg && i > 0)
	{
		if (len >= size)
			break;
		n = snprintf(buf + len, size - len, "#EXTINF:%.6f,\n/seg?cid=%u&b=%llu&e=%llu&n=%d&auth=%s\n",
			(double)p2pm3u8_dur_us(seg) / 1000000, sched->cid, seg->firstpackid, seg->lastpackid, seg->size, auth);
		if (n > 0 && n + len <= size)
			len += n;
		i--;
		seg = DLIST_NEXT(lh, seg);
	}
	pthread_mutex_unlock(&m3u8->lck);
	buf[len] = '\0';
	if (plen) *plen = len;
	return buf;
}