//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "ikcp.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>


//=====================================================================
// KCP BASIC
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// no delay min rto
const IUINT32 IKCP_RTO_MIN = 100;		// normal min rto
const IUINT32 IKCP_RTO_DEF = 200;
const IUINT32 IKCP_RTO_MAX = 60000;
const IUINT32 IKCP_CMD_PUSH = 81;		// cmd: push data
const IUINT32 IKCP_CMD_ACK  = 82;		// cmd: ack
const IUINT32 IKCP_CMD_WASK = 83;		// cmd: window probe (ask)
const IUINT32 IKCP_CMD_WINS = 84;		// cmd: window size (tell)
const IUINT32 IKCP_CMD_RST  = 85;		// cmd: reset
const IUINT32 IKCP_CMD_OOB  = 86;		// cmd: oob
const IUINT32 IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK
const IUINT32 IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS
const IUINT32 IKCP_WND_SND = 32;
const IUINT32 IKCP_WND_RCV = 128;       // must >= max fragment size
const IUINT32 IKCP_MTU_DEF = RUDP_DEFMTU;
const IUINT32 IKCP_ACK_FAST	= 32;
const IUINT32 IKCP_INTERVAL	= 100;
const IUINT32 IKCP_OVERHEAD = RUDP_OVERHEAD;
const IUINT32 IKCP_DEADLINK = 120000;   // sent but received nothing in 120s
const IUINT32 IKCP_THRESH_INIT = 64;
const IUINT32 IKCP_THRESH_MIN = 2;
const IUINT32 IKCP_PROBE_INIT = 7000;		// 7 secs to probe window size
const IUINT32 IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window
const IUINT32 IKCP_FASTACK_LIMIT = 5;		// max times to trigger fastack

#define IKCP_MAXLOG    3072

//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	*(unsigned short*)(p) = w;
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	*w = *(const unsigned short*)p;
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	*(IUINT32*)p = l;
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	*l = *(const IUINT32*)p;
#endif
	p += 4;
	return p;
}

static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline IINT32 _itimediff(IUINT32 later, IUINT32 earlier)
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
static void* (*ikcp_malloc_hook)(size_t, const char*, int) = NULL;
static void* (*ikcp_realloc_hook)(void*, size_t, const char *, int) = NULL;
static void (*ikcp_free_hook)(void *, const char *, int) = NULL;

// internal malloc
#define ikcp_malloc(size) (ikcp_malloc_hook ? ikcp_malloc_hook(size, __FILE__, __LINE__) : malloc(size))

// internal realloc
#define ikcp_realloc(ptr, size) (ikcp_realloc_hook ? ikcp_realloc_hook(ptr, size, __FILE__, __LINE__) : realloc(ptr, size))

// internal free
#define ikcp_free(ptr) (ikcp_free_hook ? ikcp_free_hook(ptr, __FILE__, __LINE__) : free(ptr))

// redefine allocator
void ikcp_allocator(void* (*new_malloc)(size_t, const char *, int),
	void* (*new_realloc)(void*, size_t, const char *, int), void (*new_free)(void*, const char *, int))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_realloc_hook = new_realloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	IKCPSEG *seg = (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
	seg->crtime = kcp->current;
	seg->kcp = kcp;
	seg->refcnt = 1;
	return seg;
}

static IKCPSEG* ikcp_segment_resize(IKCPSEG* seg, int size)
{
	return (IKCPSEG*)ikcp_realloc(seg, sizeof(IKCPSEG) + size);
}

static void ikcp_segment_ref(IKCPSEG *seg)
{
	_sync_add32(&seg->refcnt, 1);
}

static void ikcp_segment_unref(IKCPSEG *seg)
{
	if (_sync_add32(&seg->refcnt, -1) == 1)
		ikcp_free(seg);
}

// delete a segment
void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	ikcp_segment_unref(seg);
}

// check log mask
#define ikcp_canlog(_kcp, _mask) (((_mask) & (_kcp)->logmask) != 0 && (_kcp)->writelog != NULL)

// write log
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	if (ikcp_canlog(kcp, mask)) {
		char buffer[IKCP_MAXLOG];
		va_list argptr;

		va_start(argptr, fmt);
		vsprintf(buffer, fmt, argptr);
		va_end(argptr);
		kcp->writelog(buffer, kcp, kcp->user);
	}
}

// output segment
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "output: %x/%x size=%d mtu=%d/%d [%s:%d]",
			kcp->conv & kcp->mask, kcp->conv, size, kcp->mtu, kcp->maxmtu, __FUNCTION__, __LINE__);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
void ikcp_qprint(ikcpcb *kcp, const char *name, const struct IQUEUEHEAD *head)
{
	char buffer[IKCP_MAXLOG];
	int bufsize = sizeof(buffer) - 100, len;
	const struct IQUEUEHEAD *p;

	len = snprintf(buffer, bufsize, "<%s>: %lu[", name, kcp->current);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		if (len >= bufsize) {
			kcp->writelog(buffer, kcp, kcp->user);
			len = 0;
		}
		len += snprintf(buffer + len, bufsize - len, "(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) len += snprintf(buffer + len, bufsize - len, ",");
	}
	len += snprintf(buffer + len, bufsize - len, "]\n");
	kcp->writelog(buffer, kcp, kcp->user);
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
ikcpcb* ikcp_create(IUINT32 conv, IUINT32 mask, void *user, IUINT32 current)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;
	kcp->conv = conv;
	kcp->mask = mask;
	kcp->user = user;
	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;
	kcp->ts_probe = current;
	kcp->probe_wait = 0;
	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = IKCP_THRESH_INIT;
	kcp->incr = 0;
	kcp->probe = IKCP_ASK_SEND;
	kcp->maxmtu = RUDP_MAXMTU;
	kcp->mtu = IKCP_MTU_DEF;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	/*kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}*/

	iqueue_init(&kcp->snd_queue);
	iqueue_init(&kcp->rcv_queue);
	iqueue_init(&kcp->snd_buf);
	iqueue_init(&kcp->rcv_buf);
	kcp->nrcv_buf = 0;
	kcp->nsnd_buf = 0;
	kcp->nrcv_que = 0;
	kcp->nsnd_que = 0;
	kcp->loss = 0;
	kcp->acklist = NULL;
	kcp->ackblock = 0;
	kcp->ackcount = 0;
	kcp->ackpos = 0;
	kcp->ackagain = 0;
	kcp->acksn = 0;
	kcp->ackts = 0;
	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;
	kcp->current = current;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flushseg = current;
    kcp->ts_flushack = current;
	kcp->nodelay = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0x7fffffff;
	kcp->fastlimit = IKCP_FASTACK_LIMIT;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
	kcp->sendtime = kcp->recvtime = current;
	kcp->rcv_total = kcp->rcv_succ = 0;
	kcp->snd_total = kcp->snd_first = kcp->snd_succ = 0;
	kcp->breaktime = 0;
	kcp->dead_link = IKCP_DEADLINK;
	kcp->snd_timeout = 0;
	
	kcp->ack_una = 0;

	kcp->snd_bufsn = (IKCPSEG **)ikcp_malloc(kcp->snd_wnd * sizeof(IKCPSEG *));
	memset(kcp->snd_bufsn, 0, kcp->snd_wnd * sizeof(IKCPSEG *));

	kcp->rcv_bufsn = (IKCPSEG **)ikcp_malloc(kcp->rcv_wnd * sizeof(IKCPSEG *));
	memset(kcp->rcv_bufsn, 0, kcp->rcv_wnd * sizeof(IKCPSEG *));

	pthread_mutex_init(&kcp->rcv_lck, 0);
	pthread_mutex_init(&kcp->snd_lck, 0);

	kcp->ntftype = RUDP_NOTIFY_FAIL;
	kcp->output = NULL;
	kcp->notify = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	assert(kcp);
	if (kcp) {
		IKCPSEG *seg;
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			if ((kcp->ntftype & RUDP_NOTIFY_CLOSE) && kcp->notify)
				kcp->notify(RUDP_NOTIFY_CLOSE, seg, kcp, kcp->user);
			else
				ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			if ((kcp->ntftype & RUDP_NOTIFY_CLOSE) && kcp->notify)
				kcp->notify(RUDP_NOTIFY_CLOSE, seg, kcp, kcp->user);
			else
				ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if ((kcp->ntftype & RUDP_NOTIFY_CLOSE) && kcp->notify)
			kcp->notify(RUDP_NOTIFY_CLOSE, NULL, kcp, kcp->user);
		/*if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}*/
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackblock = 0;
		kcp->ackcount = 0;
		kcp->ackpos = 0;
		kcp->ackagain = 0;
		kcp->acksn = 0;
		kcp->ackts = 0;
		//kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp->snd_bufsn);
		ikcp_free(kcp->rcv_bufsn);
		pthread_mutex_destroy(&kcp->rcv_lck);
		pthread_mutex_destroy(&kcp->snd_lck);
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output/notify callback, which will be invoked by kcp
//---------------------------------------------------------------------
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}

void ikcp_setnotify(ikcpcb *kcp, int(*notify)(int cmd, IKCPSEG *seg, 
	ikcpcb *kcp, void *user))
{
	kcp->notify = notify;
}

static void ikcp_recv_nxtseg(ikcpcb *kcp)
{
	IKCPSEG *seg;
	int durtime;

	// move available data from rcv_buf -> rcv_queue
	while (!iqueue_is_empty(&kcp->rcv_buf)) {
		seg = kcp->rcv_bufsn[kcp->rcv_nxt % kcp->rcv_wnd];
		//IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		//if (seg && seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
		if (seg) {
			iqueue_del(&seg->node);
			kcp->rcv_bufsn[seg->sn % kcp->rcv_wnd] = NULL;
			kcp->nrcv_buf--;
			if (seg->sn == kcp->rcv_nxt) {
				iqueue_add_tail(&seg->node, &kcp->rcv_queue);
				kcp->nrcv_que++;
				kcp->rcv_nxt++;
			}
			else { //invalid seg
				durtime = _itimediff(kcp->current, seg->crtime);
				if (durtime > 60 * 1000) {
					if (ikcp_canlog(kcp, IKCP_LOG_ERROR)) {
						ikcp_log(kcp, IKCP_LOG_ERROR, "recv: %x/%x sn=%u frg=%d size=%d rcv_nxt=%u nrcv_que=%d/%d durtime=%d, rcv_buf timeout error [%s:%d]",
							kcp->conv & kcp->mask, kcp->conv, seg->sn, seg->frg, seg->len, kcp->rcv_nxt, kcp->nrcv_que, kcp->rcv_wnd, durtime, __FUNCTION__, __LINE__);
					}
				}
				ikcp_segment_delete(kcp, seg);
				return;
			}
		} else
			break;
	}
}

void ikcp_reset_rcvnxt(ikcpcb* kcp, IUINT32 snd_una)
{
	pthread_mutex_lock(&kcp->rcv_lck);
	if (_itimediff(snd_una, kcp->rcv_nxt) > 0)
		kcp->rcv_nxt = snd_una;
	pthread_mutex_unlock(&kcp->rcv_lck);
}

void ikcp_reset_sndnxt(ikcpcb *kcp, IUINT32 rcv_nxt)
{
	pthread_mutex_lock(&kcp->snd_lck);
	if (_itimediff(rcv_nxt, kcp->snd_nxt) > 0)
		kcp->snd_nxt = rcv_nxt;
	pthread_mutex_unlock(&kcp->snd_lck);
}

//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
//---------------------------------------------------------------------
int ikcp_recv(ikcpcb *kcp, char *buffer, int size)
{
	struct IQUEUEHEAD *p;
	int ispeek = (size < 0) ? 1 : 0;
	//int peeksize;
	int recover = 0;
	IKCPSEG *seg;
	IUINT32 len = 0;
	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue))
		return -1;

	if (size < 0) size = -size;

	/*
	peeksize = ikcp_peeksize(kcp);

	if (peeksize < 0) 
		return -2;

	if (peeksize > len) 
		return -3;
	*/

	if (kcp->nrcv_que >= kcp->rcv_wnd)
		recover = 1;

	// merge fragment
	pthread_mutex_lock(&kcp->rcv_lck);
	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; ) {
		int frg;
		seg = iqueue_entry(p, IKCPSEG, node);
		p = p->next;

		if (len + seg->len > (IUINT32)size) {
			if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
				ikcp_log(kcp, IKCP_LOG_RECV, "recv: %x/%x sn=%u: small buffer [%s:%d]",
					kcp->conv & kcp->mask, kcp->conv, seg->sn, __FUNCTION__, __LINE__);
			}
			break;
		}
		if (buffer) {
			memcpy(buffer + len, seg->data, seg->len);
			len += seg->len;
		}

		frg = seg->frg;

		if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
			ikcp_log(kcp, IKCP_LOG_RECV, "recv: %x/%x sn=%u frg=%d size=%d/%d [%s:%d]", 
				kcp->conv & kcp->mask, kcp->conv, seg->sn, seg->frg, seg->len, len, __FUNCTION__, __LINE__);
		}

		if (ispeek == 0) {
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
			kcp->nrcv_que--;
		}

		if (frg == 0)
			break;
	}

	//assert(len == peeksize);
	ikcp_recv_nxtseg(kcp);

	// fast recover
	if (kcp->nrcv_que < kcp->rcv_wnd && recover) {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp->probe |= IKCP_ASK_TELL;
	}
	pthread_mutex_unlock(&kcp->rcv_lck);

	return len;
}


//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
int ikcp_peeksize(ikcpcb *kcp)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	int length = 0;

	assert(kcp);

	pthread_mutex_lock(&kcp->rcv_lck);
	if (iqueue_is_empty(&kcp->rcv_queue)) {
		pthread_mutex_unlock(&kcp->rcv_lck);
		return -1;
	}

	seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
	if (seg->frg == 0) {
		pthread_mutex_unlock(&kcp->rcv_lck);
		return seg->len;
	}

	if (kcp->nrcv_que < seg->frg + 1) {
		pthread_mutex_unlock(&kcp->rcv_lck);
		return -1;
	}

	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) {
		seg = iqueue_entry(p, IKCPSEG, node);
		length += seg->len;
		if (seg->frg == 0) break;
	}
	pthread_mutex_unlock(&kcp->rcv_lck);

	return length;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
static inline char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);
	ptr = ikcp_encode32u(ptr, seg->ts);
	ptr = ikcp_encode32u(ptr, seg->sn);
	ptr = ikcp_encode32u(ptr, seg->una);
	ptr = ikcp_encode32u(ptr, seg->len);
	return ptr;
}

static inline int ikcp_wnd_unused(const ikcpcb *kcp)
{
	return (kcp->nrcv_que < kcp->rcv_wnd) ?
		(kcp->rcv_wnd - kcp->nrcv_que) : 0;
}

//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
//---------------------------------------------------------------------
int ikcp_send(ikcpcb *kcp, const char *data, int len, IUINT32 current)
{
	IKCPSEG *seg;
	int count, i;

	kcp->current = current;
	assert(kcp->mss > 0);
	if (len < 0) return -1;
	kcp->sendtime = kcp->current;

	// append to previous segment in streaming mode (if possible)
	if (kcp->stream != 0) {
		pthread_mutex_lock(&kcp->snd_lck);
		if (!iqueue_is_empty(&kcp->snd_queue)) {
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node);
			if (old->len < kcp->mss) {
				int capacity = kcp->mss - old->len;
				int extend = (len < capacity) ? len : capacity;
				iqueue_del_init(&old->node);
				seg = ikcp_segment_resize(old, old->len + extend);
				assert(seg);
				if (seg == NULL) {
					iqueue_add_tail(&old->node, &kcp->snd_queue);
					pthread_mutex_unlock(&kcp->snd_lck);
					return -2;
				}
				iqueue_add_tail(&seg->node, &kcp->snd_queue);
				if (data) {
					memcpy(seg->data + seg->len, data, extend);
					data += extend;
				}
				seg->len = seg->len + extend;
				seg->frg = 0;
				len -= extend;
			}
		}
		pthread_mutex_unlock(&kcp->snd_lck);
		if (len <= 0) {
			return 0;
		}
	}

	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

	if (count >= (int)IKCP_WND_RCV) return -2;
	
	if (count == 0) count = 1;

	// fragment
	for (i = 0; i < count; i++) {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len;
		seg = ikcp_segment_new(kcp, size);
		assert(seg);
		if (seg == NULL) {
			return -2;
		}
		if (data && len > 0) {
			memcpy(seg->data, data, size);
		}
		seg->len = size;
		seg->frg = (kcp->stream == 0)? (count - i - 1) : 0;

		pthread_mutex_lock(&kcp->snd_lck);
		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue);
		kcp->nsnd_que++;
		pthread_mutex_unlock(&kcp->snd_lck);

		if (data) {
			data += size;
		}
		len -= size;
	}

	ikcp_flushseg(kcp, current);
	return ikcp_cansend(kcp);
}

static void ikcp_shrink_buf(ikcpcb *kcp)
{
	struct IQUEUEHEAD *p = kcp->snd_buf.next;
	if (p != &kcp->snd_buf) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		kcp->snd_una = seg->sn;
	}
	else {
		kcp->snd_una = kcp->snd_nxt;
	}
}

int ikcp_clearsend(ikcpcb *kcp, const char *newdata, int len, IUINT32 current,
	int (*cmpseg)(IKCPSEG *seg, const char *newdata, int len))
{
	if (kcp->stream == 0 && cmpseg != NULL) {
		struct IQUEUEHEAD *p;
		IKCPSEG *seg;
		int frg = 0, drop = 0;

		pthread_mutex_lock(&kcp->snd_lck);
		p = kcp->snd_buf.next;
		while (p != &kcp->snd_buf) {
			seg = iqueue_entry(p, IKCPSEG, node);
			p = p->next;
			if (frg == 0) //new seg begin
				drop = cmpseg(seg, newdata, len);
			frg = seg->frg;
			if (drop > 0) {
				iqueue_del(&seg->node);
				kcp->snd_bufsn[seg->sn % kcp->snd_wnd] = NULL;
				kcp->nsnd_buf--;
				ikcp_shrink_buf(kcp);
				ikcp_segment_unref(seg);
			}
			else if (drop < 0) {
				pthread_mutex_unlock(&kcp->snd_lck);
				return ikcp_cansend(kcp);
			}
		}
		p = kcp->snd_queue.next;
		while (p != &kcp->snd_queue) {
			seg = iqueue_entry(p, IKCPSEG, node);
			p = p->next;
			if (frg == 0) //new seg begin
				drop = cmpseg(seg, newdata, len);
			frg = seg->frg;
			if (drop > 0) {
				iqueue_del(&seg->node);
				kcp->nsnd_que--;
				ikcp_segment_unref(seg);
			}
			else if (drop < 0) {
				pthread_mutex_unlock(&kcp->snd_lck);
				return ikcp_cansend(kcp);
			}
		}
		pthread_mutex_unlock(&kcp->snd_lck);
	}

	return ikcp_send(kcp, newdata, len, current);
}

//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
	IINT32 rto = 0;
	pthread_mutex_lock(&kcp->snd_lck);
	if (kcp->rx_srtt == 0) {
		kcp->rx_srtt = rtt;
		kcp->rx_rttval = rtt / 2;
	}	else {
		long delta = rtt - kcp->rx_srtt;
		if (delta < 0) delta = -delta;
		kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;
		kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
		if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
	}
	rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
	kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
	pthread_mutex_unlock(&kcp->snd_lck);
}

static int ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn, IUINT32 ts, IUINT32 una)
{
	//struct IQUEUEHEAD *p, *next;
	IKCPSEG *seg;

	pthread_mutex_lock(&kcp->snd_lck);
	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0) {
		pthread_mutex_unlock(&kcp->snd_lck);
		return 0;
	}
	seg = kcp->snd_bufsn[sn % kcp->snd_wnd];
	if (seg == NULL) {
		pthread_mutex_unlock(&kcp->snd_lck);
		return 0;
	}

	if (ikcp_canlog(kcp, IKCP_LOG_TRACE)) {
		ikcp_log(kcp, IKCP_LOG_TRACE, "ack=%lu nsndbuf=%d nsndque=%d snd_una=%u/%u snd_nxt=%u [%s:%d]\n", 
			sn, kcp->nsnd_buf, kcp->nsnd_que, kcp->snd_una, una, kcp->snd_nxt, __FUNCTION__, __LINE__);
		ikcp_qprint(kcp, "sndbuf", &kcp->snd_buf);
	}

	//for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
	//	seg = iqueue_entry(p, IKCPSEG, node);
	//	next = p->next;
		if (sn == seg->sn) {
			kcp->snd_succ++;
			//iqueue_del(p);
			iqueue_del(&seg->node);
			kcp->snd_bufsn[sn % kcp->snd_wnd] = NULL;
			kcp->nsnd_buf--;
			ikcp_shrink_buf(kcp);
			pthread_mutex_unlock(&kcp->snd_lck);

			if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK)) {
				ikcp_log(kcp, IKCP_LOG_IN_ACK, "input ack: %x/%x %u %u sn=%u rtt=%d rto=%d sbuf=%d una=%u [%s:%d]",
					kcp->conv & kcp->mask, kcp->conv, ts, kcp->current, sn, _itimediff(kcp->current, ts), kcp->rx_rto, kcp->nsnd_buf, una, __FUNCTION__, __LINE__);
			}
			if ((kcp->ntftype & RUDP_NOTIFY_SUCC) && kcp->notify)
				kcp->notify(RUDP_NOTIFY_SUCC, seg, kcp, kcp->user);
			else
				ikcp_segment_delete(kcp, seg);
			return 1;
	//		break;
		}
		else {
			pthread_mutex_unlock(&kcp->snd_lck);
			return 0;
		}
	//  pthread_mutex_lock(&kcp->lck);
	//	if (_itimediff(sn, seg->sn) < 0) {
	//		break;
	//	}
	//}
	//pthread_mutex_unlock(&kcp->lck);
}

static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
	//struct IQUEUEHEAD *p, *next;
	pthread_mutex_lock(&kcp->snd_lck);
	if (ikcp_canlog(kcp, IKCP_LOG_TRACE)) {
		ikcp_log(kcp, IKCP_LOG_TRACE, "nsndbuf=%d nsndque=%d snd_una=%u/%u snd_nxt=%u [%s:%d]\n",
			kcp->nsnd_buf, kcp->nsnd_que, kcp->snd_una, una, kcp->snd_nxt, __FUNCTION__, __LINE__);
		ikcp_qprint(kcp, "sndbuf", &kcp->snd_buf);
	}

	while (!iqueue_is_empty(&kcp->snd_buf)) {
	//for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		//IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		//next = p->next;
		IKCPSEG *seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
		if (_itimediff(una, seg->sn) > 0) {
			kcp->snd_succ++;
			//iqueue_del(p);
			iqueue_del(&seg->node);
			kcp->snd_bufsn[seg->sn % kcp->snd_wnd] = NULL;
			kcp->nsnd_buf--;
			ikcp_shrink_buf(kcp);
			pthread_mutex_unlock(&kcp->snd_lck);

			if ((kcp->ntftype & RUDP_NOTIFY_SUCC) && kcp->notify)
				kcp->notify(RUDP_NOTIFY_SUCC, seg, kcp, kcp->user);
			else
				ikcp_segment_delete(kcp, seg);
			pthread_mutex_lock(&kcp->snd_lck);
		} else {
			break;
		}
	}
	pthread_mutex_unlock(&kcp->snd_lck);
}

static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	struct IQUEUEHEAD *p, *next;

	pthread_mutex_lock(&kcp->snd_lck);
	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0) {
		pthread_mutex_unlock(&kcp->snd_lck);
		return;
	}

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
		else if (sn != seg->sn) {
		#ifndef IKCP_FASTACK_CONSERVE
			seg->fastack++;
		#else
			if (_itimediff(ts, seg->ts) >= 0)
				seg->fastack++;
		#endif
			if (seg->fastack >= (IUINT32)kcp->fastresend)
				kcp->ts_flushseg = kcp->current;
		}
	}
	pthread_mutex_unlock(&kcp->snd_lck);
}


//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	IUINT32 newsize;
	IUINT32 *p;

	pthread_mutex_lock(&kcp->rcv_lck);
	newsize = kcp->ackcount + 1;
	if (newsize > kcp->ackblock) {
		IUINT32 newblock;

		for (newblock = 8; newblock < newsize; newblock <<= 1);
		kcp->acklist = (IUINT32*)ikcp_realloc(kcp->acklist, newblock * sizeof(IUINT32) * 2);
		assert(kcp->acklist != NULL);
		if (kcp->acklist == NULL) {
			if (ikcp_canlog(kcp, IKCP_LOG_ERROR)) {
				ikcp_log(kcp, IKCP_LOG_ERROR, "ack push: %x/%x ackcount=%d/%d block=%d/%d: realloc error [%s:%d]",
					kcp->conv & kcp->mask, kcp->conv, kcp->ackcount, newsize, kcp->ackblock, newblock, __FUNCTION__, __LINE__);
			}
			SLEEP(3000); //TODO: wait for logging
			abort();
		}
		kcp->ackblock = newblock;
	}

	p = &kcp->acklist[kcp->ackcount * 2];
	p[0] = sn;
	p[1] = ts;
	kcp->ackcount++;
	pthread_mutex_unlock(&kcp->rcv_lck);
}

static int ikcp_ack_next(ikcpcb *kcp, IUINT32 *sn, IUINT32 *ts)
{
	if (kcp->ackpos < kcp->ackcount) {
		do {
			*sn = kcp->acklist[kcp->ackpos * 2 + 0];
			*ts = kcp->acklist[kcp->ackpos * 2 + 1];
			kcp->ackpos++;
		} while (kcp->ackpos < kcp->ackcount && _itimediff(*sn, kcp->rcv_nxt) < 0);
		return 1;
	}
	kcp->ackpos = kcp->ackcount = 0;
	return 0;
}

//---------------------------------------------------------------------
// parse data
//---------------------------------------------------------------------
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
	//struct IQUEUEHEAD *p, *prev;
	IUINT32 sn = newseg->sn;
	IUINT32 ts = newseg->ts;
	IUINT32 len = newseg->len;
	int repeat = 0;
	IKCPSEG *seg;

	pthread_mutex_lock(&kcp->rcv_lck);
	if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
		_itimediff(sn, kcp->rcv_nxt) < 0) {
		pthread_mutex_unlock(&kcp->rcv_lck);
		ikcp_segment_delete(kcp, newseg);
		return;
	}

	seg = kcp->rcv_bufsn[sn % kcp->rcv_wnd];
	//for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) {
	//	IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
	//	prev = p->prev;
		if (seg) {
			if (seg->sn == sn) {
				repeat = 1;
	//			break;
			}
			else {
				iqueue_del(&seg->node);
				kcp->rcv_bufsn[sn % kcp->rcv_wnd] = NULL;
				kcp->nrcv_buf--;
			}
		}
	//	if (_itimediff(sn, seg->sn) > 0) {
	//		break;
	//	}
	//}

	if (repeat == 0) {
		kcp->rcv_succ++;
		//iqueue_init(&newseg->node);
		//iqueue_add(&newseg->node, p);
		iqueue_add_tail(&newseg->node, &kcp->rcv_buf);
		kcp->rcv_bufsn[sn % kcp->rcv_wnd] = newseg;
		kcp->nrcv_buf++;
		ikcp_recv_nxtseg(kcp);
		pthread_mutex_unlock(&kcp->rcv_lck);

		if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
			ikcp_log(kcp, seg ? IKCP_LOG_ERROR : IKCP_LOG_IN_DATA,
				"input psh: %x/%x sn=%u/%u ts=%u nque=%d nbuf=%d rcv_nxt=%u rcv_wnd=%d len=%d ackcount:%d %s [%s:%d]",
				kcp->conv & kcp->mask, kcp->conv, sn, seg ? seg->sn : 0, ts, kcp->nrcv_que, kcp->nrcv_buf, kcp->rcv_nxt, kcp->rcv_wnd, len, kcp->ackcount, seg ? "rcv_buf error" : "", __FUNCTION__, __LINE__);
		}
		if (seg)
			ikcp_segment_delete(kcp, seg);
	} else {
		pthread_mutex_unlock(&kcp->rcv_lck);

		if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
			ikcp_log(kcp, IKCP_LOG_IN_DATA, "input dup: %x/%x sn=%u rcv_nxt=%u/%u snd_nxt=%u snd_una=%u [%s:%d]", 
				kcp->conv & kcp->mask, kcp->conv, sn, kcp->rcv_nxt, kcp->rcv_nxt + kcp->rcv_wnd, kcp->snd_nxt, kcp->snd_una, __FUNCTION__, __LINE__);
		}
		ikcp_segment_delete(kcp, newseg);
	}

	if (ikcp_canlog(kcp, IKCP_LOG_TRACE)) {
		pthread_mutex_lock(&kcp->rcv_lck);
		ikcp_log(kcp, IKCP_LOG_TRACE, "nrcvbuf=%d nrcvque=%d rcv_nxt=%u [%s:%d]\n",
			kcp->nrcv_buf, kcp->nrcv_que, kcp->rcv_nxt, __FUNCTION__, __LINE__);
		ikcp_qprint(kcp, "rcvbuf", &kcp->rcv_buf);
		ikcp_qprint(kcp, "rcvque", &kcp->rcv_queue);
		pthread_mutex_unlock(&kcp->rcv_lck);
	}
}


//---------------------------------------------------------------------
// input data
//---------------------------------------------------------------------
int ikcp_input(ikcpcb *kcp, const char *data, int size, IUINT32 current)
{
	IUINT32 prev_una = kcp->snd_una;
	IUINT32 maxack = 0, latest_ts = 0;
	int flag = 0;

	kcp->current = current;

	if (data == NULL || (int)size < (int)IKCP_OVERHEAD) return -1;

	while (1) {
		IUINT32 ts, sn, len, una, conv;
		IUINT16 wnd, mtu;
		IUINT8 cmd, frg;
		IKCPSEG *seg;
		const char *ptr;

		if (size < (int)IKCP_OVERHEAD) break;

		data = ikcp_decode32u(data, &conv);
		if ((conv & kcp->mask) != (kcp->conv & kcp->mask)) return -1;

		data = ikcp_decode8u(data, &cmd);
		data = ikcp_decode8u(data, &frg);
		data = ikcp_decode16u(data, &wnd);
		data = ikcp_decode32u(data, &ts);
		data = ikcp_decode32u(data, &sn);
		data = ikcp_decode32u(data, &una);
		data = ikcp_decode32u(data, &len);

		size -= IKCP_OVERHEAD;

		if (ikcp_canlog(kcp, IKCP_LOG_INPUT)) {
			ikcp_log(kcp, IKCP_LOG_INPUT, "input: %x/%x cmd=%d %u %u sn=%u frg=%d len=%d una=%u/%u snd_nxt=%u wnd:%d cwnd:%d size:%d/%d sbuf:%d sque:%d rbuf:%d rque:%d sndts:%u rcv_nxt:%u rcv_wnd:%d ack:%d/%d [%s:%d]", 
				kcp->conv & kcp->mask, kcp->conv, cmd, current, ts, sn, frg, len, una, kcp->snd_una, kcp->snd_nxt, wnd, kcp->cwnd, len, size, kcp->nsnd_buf, kcp->nsnd_que, kcp->nrcv_buf, kcp->nrcv_que, kcp->ts_flushseg, kcp->rcv_nxt, kcp->rcv_wnd, kcp->ackcount, kcp->ackpos, __FUNCTION__, __LINE__);
		}

		if ((long)size < (long)len || (int)len < 0) return -2;

		if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) 
			return -3;

		kcp->recvtime = current;
		kcp->rmt_wnd = wnd;
		ikcp_parse_una(kcp, una);

		if (cmd == IKCP_CMD_ACK) {
			ptr = data;
			while (1) {
				if (ikcp_parse_ack(kcp, sn, ts, una)) {
					if (_itimediff(current, ts) >= 0)
						ikcp_update_ack(kcp, _itimediff(current, ts));

					if (flag == 0) {
						flag = 1;
						maxack = sn;
						latest_ts = ts;
					}
					else {
						if (_itimediff(sn, maxack) > 0) {
#ifndef IKCP_FASTACK_CONSERVE
							maxack = sn;
							latest_ts = ts;
#else
							if (_itimediff(ts, latest_ts) > 0) {
								maxack = sn;
								latest_ts = ts;
							}
#endif
						}
					}
				}
				if (ptr + sizeof(IUINT32) * 2 > data + len) break;
				ptr = ikcp_decode32u(ptr, &sn);
				ptr = ikcp_decode32u(ptr, &ts);
			}

			if (_itimediff(una, kcp->ack_una) > 0)
				kcp->ack_una = una;
			if (_itimediff(kcp->snd_una, kcp->ack_una) > 0) //try to skip dropped segs
				kcp->probe |= IKCP_ASK_SEND;
		}
		else if (cmd == IKCP_CMD_PUSH) {
			_sync_add64(&kcp->rcv_total, 1);
			if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) {
				if (_itimediff(sn, kcp->rcv_nxt) >= 0) {
					seg = ikcp_segment_new(kcp, len);
					seg->conv = conv;
					seg->cmd = cmd;
					seg->frg = frg;
					seg->wnd = wnd;
					seg->ts = ts;
					seg->sn = sn;
					seg->una = una;
					seg->len = len;

					if (len > 0) {
						memcpy(seg->data, data, len);
					}

					ikcp_parse_data(kcp, seg);
				}

				ikcp_ack_push(kcp, sn, ts); //TODO:ack for resend seg
				ikcp_flushack(kcp, current, IKCP_ACK_FAST);
			}
			else {
				if (ikcp_canlog(kcp, IKCP_LOG_ERROR)) {
					ikcp_log(kcp, IKCP_LOG_ERROR, "input: %x/%x cmd=%d %u %u sn=%u frg=%d len=%d una=%u/%u snd_nxt=%u wnd:%d cwnd:%d size:%d/%d sbuf:%d sque:%d rbuf:%d rque:%d sndts:%u rcv_nxt:%u rcv_wnd:%d ack:%d/%d, recv sn in advance error [%s:%d]",
						kcp->conv & kcp->mask, kcp->conv, cmd, current, ts, sn, frg, len, una, kcp->snd_una, kcp->snd_nxt, wnd, kcp->cwnd, len, size, kcp->nsnd_buf, kcp->nsnd_que, kcp->nrcv_buf, kcp->nrcv_que, kcp->ts_flushseg, kcp->rcv_nxt, kcp->rcv_wnd, kcp->ackcount, kcp->ackpos, __FUNCTION__, __LINE__);
				}
			}
		}
		else if (cmd == IKCP_CMD_WASK) {
			// ready to send back IKCP_CMD_WINS in ikcp_flushack
			// tell remote my window size
			if (len >= 2) {
				ikcp_decode16u(data, &mtu);
				ikcp_setmtu(kcp, mtu);
			}
			ikcp_reset_rcvnxt(kcp, sn);
			ikcp_reset_sndnxt(kcp, una);
			kcp->probe |= IKCP_ASK_TELL;
			if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE)) {
				ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe: %x/%x rcvnxt:%u/%u sndnxt:%u/%u [%s:%d]", kcp->conv & kcp->mask, kcp->conv, kcp->rcv_nxt, sn, kcp->snd_nxt, una, __FUNCTION__, __LINE__);
			}
		}
		else if (cmd == IKCP_CMD_WINS) {
			// do nothing else, but skip dropped segs
			if (len >= 2) {
				ikcp_decode16u(data, &mtu);
				ikcp_setmtu(kcp, mtu);
			}
			ikcp_reset_rcvnxt(kcp, sn);
			ikcp_reset_sndnxt(kcp, una);
			if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS)) {
				ikcp_log(kcp, IKCP_LOG_IN_WINS, "input wins: %x/%x %d rcvnxt:%u/%u sndnxt:%u/%u [%s:%d]", kcp->conv & kcp->mask, kcp->conv, wnd, kcp->rcv_nxt, sn, kcp->snd_nxt, una, __FUNCTION__, __LINE__);
			}
		}
		else {
			return -3;
		}

		data += len;
		size -= len;
	}

	if (flag != 0) {
		ikcp_parse_fastack(kcp, maxack, latest_ts);
	}

	if (_itimediff(kcp->snd_una, prev_una) > 0) {
		if (kcp->nocwnd == 0) {
			pthread_mutex_lock(&kcp->snd_lck);
			if (kcp->cwnd < kcp->rmt_wnd) {
				IUINT32 mss = kcp->mss;
				if (kcp->cwnd < kcp->ssthresh) {
					kcp->cwnd++;
					kcp->incr += mss;
				} else {
					if (kcp->incr < mss) kcp->incr = mss;
					kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
					if ((kcp->cwnd + 1) * mss <= kcp->incr) {
						#if 1
						kcp->cwnd = (kcp->incr + mss - 1) / ((mss > 0) ? mss : 1);
						#else
						kcp->cwnd++;
						#endif
					}
				}
				if (kcp->cwnd > kcp->rmt_wnd) {
					kcp->cwnd = kcp->rmt_wnd;
					kcp->incr = kcp->rmt_wnd * mss;
				}
			}
			pthread_mutex_unlock(&kcp->snd_lck);
		}
		else if (kcp->nocwnd == 1) {
			pthread_mutex_lock(&kcp->snd_lck);
			if (kcp->cwnd < kcp->rmt_wnd) {
				kcp->cwnd += (kcp->cwnd < kcp->ssthresh) ? kcp->cwnd : 1;
				if (kcp->cwnd > kcp->rmt_wnd)
					kcp->cwnd = kcp->rmt_wnd;
			}
			pthread_mutex_unlock(&kcp->snd_lck);
		}

		ikcp_flushseg(kcp, current);
		if (ikcp_cansend(kcp) > 0) {
			if ((kcp->ntftype & RUDP_NOTIFY_NEXT) && kcp->notify)
				kcp->notify(RUDP_NOTIFY_NEXT, NULL, kcp, kcp->user);
		}
	}

	return 0;
}

//---------------------------------------------------------------------
// ikcp_flushack
//---------------------------------------------------------------------
IINT32 ikcp_flushack(ikcpcb *kcp, IUINT32 current, int ackfast)
{
	char buffer[RUDP_DEFMTU]; // kcp->buffer;
	char *ptr = buffer;
	int size, mtu = _imin_(kcp->mtu, RUDP_DEFMTU);
	int interval = 0;
	IKCPSEG initseg;
	IINT32 sn = 0, ts = 0;
	IUINT32 probe = 0;

    kcp->current = current;

    pthread_mutex_lock(&kcp->rcv_lck);	
    if (ackfast <= 0 || kcp->ackcount < ackfast) {
        interval = _itimediff(kcp->ts_flushack, current);
        if (interval > 0 && interval > kcp->interval)
            interval = kcp->interval;
    }

	initseg.conv = kcp->conv;
	initseg.frg = 0;
	initseg.wnd = ikcp_wnd_unused(kcp);
	initseg.una = kcp->rcv_nxt;

	if (interval > 0) {
		pthread_mutex_unlock(&kcp->rcv_lck);
	}
	else {
		interval = kcp->interval;
		kcp->ts_flushack = kcp->current + interval;

		// flush acknowledges
		initseg.cmd = IKCP_CMD_ACK;
		if (ikcp_ack_next(kcp, &sn, &ts)) {
			initseg.sn = sn;
			initseg.ts = ts;
			ptr = buffer + IKCP_OVERHEAD;
			while (kcp->ackpos > 0 && ikcp_ack_next(kcp, &sn, &ts)) {
				size = (int)(ptr - buffer);
				if (size + sizeof(IUINT32) * 2 <= mtu) {
					ptr = ikcp_encode32u(ptr, sn);
					ptr = ikcp_encode32u(ptr, ts);
				}
				else {
					pthread_mutex_unlock(&kcp->rcv_lck);

					if (ikcp_canlog(kcp, IKCP_LOG_OUT_ACK)) {
						ikcp_log(kcp, IKCP_LOG_OUT_ACK,
							"flush ack: %x/%x %u sn=%u ts=%u ack=%d/%d nque=%d nbuf=%d snd_nxt=%u snd_una=%u rcv_nxt=%u rcv_wnd=%d, xsum=%d [%s:%d]",
							kcp->conv & kcp->mask, kcp->conv, current, initseg.sn, initseg.ts, kcp->ackcount, kcp->ackpos,
							kcp->nsnd_que, kcp->nsnd_buf, kcp->snd_nxt, kcp->snd_una, kcp->rcv_nxt, kcp->rcv_wnd, kcp->xmit, __FUNCTION__, __LINE__);
					}

					initseg.len = size - IKCP_OVERHEAD;
					ikcp_encode_seg(buffer, &initseg);
					ikcp_output(kcp, buffer, size);

					pthread_mutex_lock(&kcp->rcv_lck);
					initseg.wnd = ikcp_wnd_unused(kcp);
					initseg.una = kcp->rcv_nxt;
					initseg.sn = sn;
					initseg.ts = ts;
					ptr = buffer + IKCP_OVERHEAD;
				}
			}
			kcp->ackagain = 1;
			kcp->acksn = sn;
			kcp->ackts = ts;
		}
		else if (kcp->ackagain) {
			kcp->ackagain = 0;
			initseg.sn = kcp->acksn;
			initseg.ts = kcp->ackts;
			ptr = buffer + IKCP_OVERHEAD;
		}
		pthread_mutex_unlock(&kcp->rcv_lck);

		size = (int)(ptr - buffer);
		if (size >= IKCP_OVERHEAD) {
			if (ikcp_canlog(kcp, IKCP_LOG_OUT_ACK)) {
				ikcp_log(kcp, IKCP_LOG_OUT_ACK,
					"flush ack: %x/%x %u sn=%u ts=%u nque=%d nbuf=%d snd_nxt=%u snd_una=%u rcv_nxt=%u rcv_wnd=%d, xsum=%d [%s:%d]",
					kcp->conv & kcp->mask, kcp->conv, current, initseg.sn, initseg.ts,
					kcp->nsnd_que, kcp->nsnd_buf, kcp->snd_nxt, kcp->snd_una, kcp->rcv_nxt, kcp->rcv_wnd, kcp->xmit, __FUNCTION__, __LINE__);
			}

			initseg.len = size - IKCP_OVERHEAD;
			ikcp_encode_seg(buffer, &initseg);
		}
	}

	// probe window size (if remote window size equals zero)
	pthread_mutex_lock(&kcp->snd_lck);
	probe = kcp->probe;
	kcp->probe = 0; //TODO:atomic
	if (kcp->rmt_wnd == 0) {
		if (kcp->probe_wait == 0) {
			kcp->probe_wait = IKCP_PROBE_INIT;
			kcp->ts_probe = current + kcp->probe_wait;
		}
		else {
			if (_itimediff(current, kcp->ts_probe) >= 0) {
				if (kcp->probe_wait < IKCP_PROBE_INIT)
					kcp->probe_wait = IKCP_PROBE_INIT;
				kcp->probe_wait += kcp->probe_wait / 2;
				if (kcp->probe_wait > IKCP_PROBE_LIMIT)
					kcp->probe_wait = IKCP_PROBE_LIMIT;
				kcp->ts_probe = current + kcp->probe_wait;
				probe |= IKCP_ASK_SEND;
			}
		}
	}
	else {
		kcp->probe_wait = 0;
	}
	initseg.sn = kcp->snd_una;
	pthread_mutex_unlock(&kcp->snd_lck);

	initseg.ts = 0;
	initseg.len = 2; //kcp->maxmtu

	// flush window probing commands
	if (probe & IKCP_ASK_SEND) {
		initseg.cmd = IKCP_CMD_WASK;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD + initseg.len > mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &initseg);
		ptr = ikcp_encode16u(ptr, kcp->maxmtu);

		if (ikcp_canlog(kcp, IKCP_LOG_OUT_PROBE)) {
			ikcp_log(kcp, IKCP_LOG_OUT_PROBE,
				"flush wack: %x/%x %u %u %d sn=%u rmt_wnd=%d rto=%d nque=%d nbuf=%d snd_nxt=%u snd_una=%u rcv_nxt=%u rcv_wnd=%d, xsum=%d [%s:%d]",
				kcp->conv & kcp->mask, kcp->conv, current, kcp->ts_probe, kcp->probe_wait, initseg.sn, kcp->rmt_wnd, kcp->rx_rto,
				kcp->nsnd_que, kcp->nsnd_buf, kcp->snd_nxt, kcp->snd_una, kcp->rcv_nxt, kcp->rcv_wnd, kcp->xmit, __FUNCTION__, __LINE__);
		}
	}

	// flush window probing commands
	if (probe & IKCP_ASK_TELL) {
		initseg.cmd = IKCP_CMD_WINS;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD + initseg.len > mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &initseg);
		ptr = ikcp_encode16u(ptr, kcp->maxmtu);
	}

	// flush remain segments
	size = (int)(ptr - buffer);
	if (size > 0) {
		ikcp_output(kcp, buffer, size);
	}
    return interval;
}

//---------------------------------------------------------------------
// ikcp_flush
//---------------------------------------------------------------------
IINT32 ikcp_flushseg(ikcpcb *kcp, IUINT32 current)
{
	char buffer[RUDP_MAXMTU]; // kcp->buffer;
	char *ptr = buffer;
	int size, need;
	IUINT32 cwnd = 0;
	IUINT32 rtomin = 0;
	struct IQUEUEHEAD *p, *next;
	int old = 0;
	int change = 0;
	int lost = 0;
	IKCPSEG *newseg;
	IINT32 interval;
	IKCPSEG *xbuf[1024];
	IKCPSEG **xmitq = xbuf;
	int i, xmitnum = 0;
	int snd_timeout = kcp->snd_timeout;

	kcp->current = current;
	if (ikcp_canlog(kcp, IKCP_LOG_FLUSH)) {
		// calculate window size
		cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
		if (kcp->nocwnd <= 1) cwnd = _imin_(kcp->cwnd, cwnd);
		ikcp_log(kcp, IKCP_LOG_FLUSH, "flush seg: %x/%x %d sndts:%u/%u ack:%d/%d nque:%d nbuf:%d snd_nxt:%u/%u snd_una:%u wnd:%d rcv_nxt:%u xsum:%d [%s:%d]",
			kcp->conv & kcp->mask, kcp->conv, current - kcp->ts_flushseg, kcp->ts_flushseg, current,
			kcp->ackcount, kcp->ackpos, kcp->nsnd_que, kcp->nsnd_buf, kcp->snd_nxt, kcp->snd_una + cwnd, kcp->snd_una, cwnd, kcp->rcv_nxt, kcp->xmit, __FUNCTION__, __LINE__);
	}

	pthread_mutex_lock(&kcp->snd_lck);
	if (kcp->snd_wnd > sizeof(xbuf) / sizeof(xbuf[0]))
		xmitq = (IKCPSEG **)ikcp_malloc(kcp->snd_wnd * sizeof(IKCPSEG *));

	//resend data in snd_buf
    interval = _itimediff(kcp->ts_flushseg, current);
	if (interval <= 0) {
		kcp->ts_flushseg = current + IKCP_RTO_MAX;
		if (kcp->nsnd_buf > 0) {
			newseg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			if (_itimediff(current, newseg->crtime) > kcp->dead_link)
				old = 1;

			//rtomin = (kcp->nodelay <= 1) ? (kcp->rx_rto >> 3) : 0;
			rtomin = (kcp->nodelay <= 1) ? _imax_(kcp->rx_rto / 2, 15) : 0;

			// flush data segments
			for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
				newseg = iqueue_entry(p, IKCPSEG, node);
				next = p->next;
				int needsend = 0;
				if (newseg->xmit == 0) {
					needsend = 1;
					newseg->xmit++;
					newseg->rto = kcp->rx_rto;
					newseg->resendts = kcp->current + newseg->rto + rtomin;
				}
				else if (_itimediff(current, newseg->resendts) >= 0) {
					needsend = 1;
					newseg->xmit++;
					kcp->xmit++;
					if (kcp->nodelay == 0)
						newseg->rto += _imax_(newseg->rto, (IUINT32)kcp->rx_rto);
					else if (kcp->nodelay == 1)
						newseg->rto += _imax_(newseg->rto / 2, (IUINT32)kcp->rx_rto);
					else if (kcp->nodelay == 2)
						newseg->rto += newseg->rto / 2;
					else
						newseg->rto += kcp->rx_rto / 2;
					newseg->resendts = kcp->current + _imin_(newseg->rto, IKCP_RTO_MAX); //TODO: max 60s
					lost++;
				}
				else if (newseg->fastack >= (IUINT32)kcp->fastresend) {
					if ((int)newseg->xmit <= kcp->fastlimit ||
						kcp->fastlimit <= 0) {
						needsend = 1;
						newseg->xmit++;
						newseg->fastack = 0;
						newseg->resendts = kcp->current + _ibound_(kcp->rx_rto, newseg->rto, IKCP_RTO_MAX);
						change++;
					}
				}

				if (_itimediff(newseg->resendts, kcp->ts_flushseg) < 0)
					kcp->ts_flushseg = newseg->resendts;

				if (needsend) {
					newseg->ts = kcp->current;
					newseg->wnd = ikcp_wnd_unused(kcp);
					newseg->una = kcp->rcv_nxt;

					ikcp_segment_ref(newseg);
					xmitq[xmitnum++] = newseg;

					if (snd_timeout > 0 && _itimediff(current, newseg->crtime) >= snd_timeout) {
						kcp->loss++;
						iqueue_del(p);
						kcp->snd_bufsn[newseg->sn % kcp->snd_wnd] = NULL;
						kcp->nsnd_buf--;
						ikcp_shrink_buf(kcp);
					}
				}
			}

			if (kcp->nocwnd == 0) {
				// update ssthresh
				cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
				if (kcp->nocwnd <= 1) cwnd = _imin_(kcp->cwnd, cwnd);

				if (change) {
					IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
					kcp->ssthresh = inflight / 2;
					if (kcp->ssthresh < IKCP_THRESH_MIN)
						kcp->ssthresh = IKCP_THRESH_MIN;
					kcp->cwnd = kcp->ssthresh + (IUINT32)kcp->fastresend;
					kcp->incr = kcp->cwnd * kcp->mss;
				}

				if (lost) {
					kcp->ssthresh = cwnd / 2;
					if (kcp->ssthresh < IKCP_THRESH_MIN)
						kcp->ssthresh = IKCP_THRESH_MIN;
					kcp->cwnd = 1;
					kcp->incr = kcp->mss;
				}

				if (kcp->cwnd < 1) {
					kcp->cwnd = 1;
					kcp->incr = kcp->mss;
				}
			}
			else if (kcp->nocwnd == 1) {
				// update ssthresh
				if (lost) {
					kcp->ssthresh = kcp->cwnd * 2 / 3;
					if (kcp->ssthresh < IKCP_THRESH_MIN)
						kcp->ssthresh = IKCP_THRESH_MIN;
					kcp->cwnd = kcp->ssthresh;
				}
			}
		}
	}

	// move data from snd_queue to snd_buf
	while (!iqueue_is_empty(&kcp->snd_queue) && xmitnum < kcp->snd_wnd) {
		// calculate window size
		cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
		if (kcp->nocwnd <= 1) cwnd = _imin_(kcp->cwnd, cwnd);
		if (_itimediff(kcp->snd_nxt, kcp->snd_una) >= cwnd) break;

		// calculate resent
		//rtomin = (kcp->nodelay <= 1) ? (kcp->rx_rto >> 3) : 0;
		rtomin = (kcp->nodelay <= 1) ? _imax_(kcp->rx_rto / 2, 15) : 0;

		// move data from snd_queue to snd_buf
		newseg = kcp->snd_bufsn[kcp->snd_nxt % kcp->snd_wnd];
		if (newseg) { //invalid seg
			if (ikcp_canlog(kcp, IKCP_LOG_ERROR)) {
				ikcp_log(kcp, IKCP_LOG_ERROR, "oldseg: %x/%x sn=%u snd_nxt=%u snd_una=%u: snd_nxt error [%s:%d]",
					kcp->conv & kcp->mask, kcp->conv, newseg->sn, kcp->snd_nxt, kcp->snd_una, __FUNCTION__, __LINE__);
			}
			iqueue_del(&newseg->node);
			kcp->snd_bufsn[kcp->snd_nxt % kcp->snd_wnd] = NULL;
			kcp->nsnd_buf--;
			ikcp_shrink_buf(kcp);
			ikcp_segment_delete(kcp, newseg);
		}

		newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
		iqueue_del(&newseg->node);
		kcp->nsnd_que--;

		newseg->conv = kcp->conv;
		newseg->cmd = IKCP_CMD_PUSH;
		newseg->wnd = ikcp_wnd_unused(kcp);
		newseg->ts = kcp->current;
		newseg->sn = kcp->snd_nxt;
		newseg->una = kcp->rcv_nxt;
		newseg->rto = kcp->rx_rto;
		newseg->fastack = 0;
		newseg->resendts = kcp->current + newseg->rto + rtomin;
		newseg->xmit = 1;

		if (snd_timeout > 0 && _itimediff(current, newseg->crtime) >= snd_timeout)
			kcp->loss++;
		else {
			iqueue_add_tail(&newseg->node, &kcp->snd_buf);
			kcp->snd_bufsn[kcp->snd_nxt % kcp->snd_wnd] = newseg;
			kcp->nsnd_buf++;
			kcp->snd_nxt++;

			if (_itimediff(newseg->resendts, kcp->ts_flushseg) < 0)
				kcp->ts_flushseg = newseg->resendts;
		}
		
		ikcp_segment_ref(newseg);
		xmitq[xmitnum++] = newseg;
	}

	interval = _itimediff(kcp->ts_flushseg, current);
	if (interval <= 0 || interval > kcp->interval)
		interval = kcp->interval;
	pthread_mutex_unlock(&kcp->snd_lck);

	//send all in xmitq
	for (i = 0; i < xmitnum; i++) {
		newseg = xmitq[i];
		if (snd_timeout > 0 && _itimediff(current, newseg->crtime) >= snd_timeout) {
			if (ikcp_canlog(kcp, IKCP_LOG_BREAK)) {
				ikcp_log(kcp, IKCP_LOG_BREAK,
					"fail: %x/%x %u %u %u sn=%u size=%d xmit=%d rto=%d nque=%d/%d nbuf=%d rcv_nxt=%u snd_nxt=%u snd_una=%u rcv_wnd=%d rmt_wnd=%d cwnd=%d snd_wnd=%d xsum=%d ackcount:%d %p [%s:%d]",
					kcp->conv & kcp->mask, kcp->conv, newseg->ts, current, newseg->resendts, newseg->sn, newseg->len, newseg->xmit, newseg->rto,
					kcp->nsnd_que, kcp->snd_wnd, kcp->nsnd_buf, kcp->rcv_nxt, kcp->snd_nxt, kcp->snd_una, newseg->wnd, kcp->rmt_wnd, kcp->cwnd, kcp->snd_wnd, kcp->xmit, kcp->ackcount, newseg, __FUNCTION__, __LINE__);
			}
			
			if ((kcp->ntftype & RUDP_NOTIFY_FAIL) && kcp->notify)
                kcp->notify(RUDP_NOTIFY_FAIL, newseg, kcp, kcp->user);
            else
                ikcp_segment_delete(kcp, newseg);
        }
		else if (_itimediff(newseg->sn, kcp->snd_una) >= 0) {
			_sync_add64(&kcp->snd_total, 1);
			if (newseg->xmit == 1)
				_sync_add64(&kcp->snd_first, 1);
			if (ikcp_canlog(kcp, newseg->xmit > 1 ? IKCP_LOG_RESEND : IKCP_LOG_SEND)) {
				ikcp_log(kcp, newseg->xmit > 1 ? IKCP_LOG_RESEND : IKCP_LOG_SEND,
                    "resend: %x/%x %u %u %u sn=%u size=%d xmit=%d rto=%d nque=%d/%d nbuf=%d rcv_nxt=%u snd_nxt=%u snd_una=%u rcv_wnd=%d rmt_wnd=%d cwnd=%d snd_wnd=%d xsum=%d ackcount:%d %p [%s:%d]",
					kcp->conv & kcp->mask, kcp->conv, newseg->ts, current, newseg->resendts, newseg->sn, newseg->len, newseg->xmit, newseg->rto,
					kcp->nsnd_que, kcp->snd_wnd, kcp->nsnd_buf, kcp->rcv_nxt, kcp->snd_nxt, kcp->snd_una, newseg->wnd, kcp->rmt_wnd, kcp->cwnd, kcp->snd_wnd, kcp->xmit, kcp->ackcount, newseg, __FUNCTION__, __LINE__);
			}

			size = (int)(ptr - buffer);
			need = IKCP_OVERHEAD + newseg->len;
			if (size + need > (int)kcp->mtu) {
				ikcp_output(kcp, buffer, size);
				ptr = buffer;
			}
			newseg->wnd = ikcp_wnd_unused(kcp);
			newseg->una = kcp->rcv_nxt;
			ptr = ikcp_encode_seg(ptr, newseg);
			if (newseg->len > 0) {
				memcpy(ptr, newseg->data, newseg->len);
				ptr += newseg->len;
			}
		}
        ikcp_segment_unref(newseg);
    }

	if (xmitq != xbuf)
		ikcp_free(xmitq);
	
	// flush remain segments
	size = (int)(ptr - buffer);
	if (size > 0) {
		ikcp_output(kcp, buffer, size);
	}

	if (old && _itimediff(current, kcp->recvtime) > kcp->dead_link &&
		(kcp->breaktime == 0 || _itimediff(current, kcp->breaktime) > kcp->dead_link)) {
		kcp->breaktime = current;
		if ((kcp->ntftype & RUDP_NOTIFY_BREAK) && kcp->notify)
			kcp->notify(RUDP_NOTIFY_BREAK, NULL, kcp, kcp->user);
	}
	return interval;
}


//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//---------------------------------------------------------------------
/*IINT32 ikcp_update(ikcpcb *kcp, IUINT32 current)
{
	IINT32 slap;

	pthread_mutex_lock(&kcp->lck);
	kcp->current = current;

	if (kcp->updated == 0) {
		kcp->updated = 1;
		kcp->ts_flush = kcp->current;
	}

	slap = _itimediff(current, kcp->ts_flush);
	if (slap >= 10000 || slap < -10000) {
		kcp->ts_flush = kcp->current;
		slap = 0;
	}
	pthread_mutex_unlock(&kcp->lck);

	if (slap >= 0) {
		slap = ikcp_flush(kcp, current);
	} else {
		slap = -slap;
		if (slap > kcp->interval)
			slap = kcp->interval;
	}
	return slap;
}*/


//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
/*IUINT32 ikcp_check(ikcpcb *kcp, IUINT32 current)
{
	IUINT32 ts_flush = kcp->ts_flush;
	IINT32 tm_flush = 0x7fffffff;
	IINT32 tm_packet = 0x7fffffff;
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;

	if (kcp->updated == 0) {
		return current;
	}

	if (_itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000) {
		ts_flush = current;
	}

	if (_itimediff(current, ts_flush) >= 0) {
		return current;
	}

	tm_flush = _itimediff(ts_flush, current);

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0) {
			kcp->ts_flush = current;
			return current;
		}
		if (diff < tm_packet) tm_packet = diff;
	}

	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	if (minimal >= kcp->interval) minimal = kcp->interval;

	return current + minimal;
}*/


int ikcp_setmtu(ikcpcb *kcp, IUINT16 mtu)
{
	//char *buffer;
	if (mtu < 50 || mtu < IKCP_OVERHEAD)
		return -1;
	/*buffer = (char*)ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);
	if (buffer == NULL)
		return -2;*/
	pthread_mutex_lock(&kcp->snd_lck);
	kcp->mtu = (mtu < kcp->maxmtu) ? mtu : kcp->maxmtu;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	//ikcp_free(kcp->buffer);
	//kcp->buffer = buffer;
	pthread_mutex_unlock(&kcp->snd_lck);
	return 0;
}

int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}

int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
	if (nodelay >= 0) {
		kcp->nodelay = nodelay;
		if (nodelay) {
			kcp->rx_minrto = IKCP_RTO_NDL;	
		}	
		else {
			kcp->rx_minrto = IKCP_RTO_MIN;
		}
	}
	if (interval >= 0) {
		if (interval > 5000) interval = 5000;
		else if (interval < 10) interval = 10;
		kcp->interval = interval;
	}
	if (resend > 0) {
		kcp->fastresend = resend;
	}
	else {
		kcp->fastresend = 0x7fffffff;
	}
	if (nc >= 0) {
		kcp->nocwnd = nc;
	}
	return 0;
}


int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	
	if (kcp) {
		pthread_mutex_lock(&kcp->snd_lck);
		if (sndwnd > 0 && kcp->snd_wnd != sndwnd) {
			kcp->snd_wnd = sndwnd;

			ikcp_free(kcp->snd_bufsn);
			kcp->snd_bufsn = (IKCPSEG **)ikcp_malloc(kcp->snd_wnd * sizeof(IKCPSEG *));
			memset(kcp->snd_bufsn, 0, kcp->snd_wnd * sizeof(IKCPSEG *));
			for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
				seg = iqueue_entry(p, IKCPSEG, node);
				kcp->snd_bufsn[seg->sn % kcp->snd_wnd] = seg;
			}
		}
		pthread_mutex_unlock(&kcp->snd_lck);
		pthread_mutex_lock(&kcp->rcv_lck);
		if (rcvwnd > 0 && kcp->rcv_wnd != rcvwnd) {   // must >= max fragment size
			kcp->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);

			ikcp_free(kcp->rcv_bufsn);
			kcp->rcv_bufsn = (IKCPSEG **)ikcp_malloc(kcp->rcv_wnd * sizeof(IKCPSEG *));
			memset(kcp->rcv_bufsn, 0, kcp->rcv_wnd * sizeof(IKCPSEG *));
			for (p = kcp->rcv_buf.next; p != &kcp->rcv_buf; p = p->next) {
				seg = iqueue_entry(p, IKCPSEG, node);
				kcp->rcv_bufsn[seg->sn % kcp->rcv_wnd] = seg;
			}
	    }
		pthread_mutex_unlock(&kcp->rcv_lck);
	}
	return 0;
}

int ikcp_cansend(const ikcpcb *kcp)
{
	return (kcp->snd_wnd > kcp->nsnd_que) ?
		(kcp->snd_wnd - kcp->nsnd_que) : 0;
}

// read conv
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}

int ikcp_rstcmd(char *ptr, IUINT32 conv)
{
	memset(ptr, 0, IKCP_OVERHEAD);
	ptr = ikcp_encode32u(ptr, conv);
	*ptr = IKCP_CMD_RST;
	return IKCP_OVERHEAD;
}

int ikcp_chkrst(const char *ptr)
{
	return *(ptr + 4) == IKCP_CMD_RST ? 1 : 0;
}

int ikcp_oobcmd(char *ptr, IUINT32 conv, const char *data, int len)
{
	memcpy(ptr + IKCP_OVERHEAD, data, len);
	memset(ptr, 0, IKCP_OVERHEAD);
	ptr = ikcp_encode32u(ptr, conv);
	*ptr = IKCP_CMD_OOB;
	return IKCP_OVERHEAD + len;
}

int ikcp_chkoob(const char *ptr)
{
	return *(ptr + 4) == IKCP_CMD_OOB ? 1 : 0;
}

IINT32 ikcp_idletime(ikcpcb *kcp)
{
	IINT32 send = _itimediff(kcp->current, kcp->sendtime);
	IINT32 recv = _itimediff(kcp->current, kcp->recvtime);
	return (send > recv) ? recv : send;
}

int ikcp_broken(ikcpcb *kcp)
{
	IKCPSEG *seg;

	pthread_mutex_lock(&kcp->snd_lck);
	if (kcp->nsnd_buf > 0) {
		seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
		if (_itimediff(kcp->current, seg->crtime) > kcp->dead_link &&
			_itimediff(kcp->current, kcp->recvtime) > kcp->dead_link) {
			pthread_mutex_unlock(&kcp->snd_lck);
			return 1;
		}
	}
	pthread_mutex_unlock(&kcp->snd_lck);
	return 0;
}