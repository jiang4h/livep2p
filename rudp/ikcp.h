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
#ifndef __IKCP_H__
#define __IKCP_H__

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

#ifdef _WIN32
#include "windows.h"
#define pthread_mutex_t           CRITICAL_SECTION
#define pthread_mutex_lock(a)     EnterCriticalSection(a)
#define pthread_mutex_unlock(a)   LeaveCriticalSection(a)
#define pthread_mutex_init(a,b)   InitializeCriticalSection(a)
#define pthread_mutex_destroy(a)  DeleteCriticalSection(a)
#define SLEEP                     Sleep
#define _sync_add32(pint32,inc)   InterlockedExchangeAdd(pint32,inc)
#define _sync_add64(pint64,inc)   InterlockedExchangeAdd64(pint64,inc)
#else
#include <pthread.h>
#define SLEEP(x)                  usleep((x) * 1000)
#define _sync_add32(pint32,inc)   __sync_fetch_and_add(pint32,inc)
#define _sync_add64(pint64,inc)   __sync_fetch_and_add(pint64,inc)
#endif

//=====================================================================
// 32BIT INTEGER DEFINITION 
//=====================================================================
#ifndef __INTEGER_32_BITS__
#define __INTEGER_32_BITS__
#if defined(_WIN64) || defined(WIN64) || defined(__amd64__) || \
	defined(__x86_64) || defined(__x86_64__) || defined(_M_IA64) || \
	defined(_M_AMD64)
	typedef unsigned int ISTDUINT32;
	typedef int ISTDINT32;
#elif defined(_WIN32) || defined(WIN32) || defined(__i386__) || \
	defined(__i386) || defined(_M_X86)
	typedef unsigned long ISTDUINT32;
	typedef long ISTDINT32;
#elif defined(__MACOS__)
	typedef UInt32 ISTDUINT32;
	typedef SInt32 ISTDINT32;
#elif defined(__APPLE__) && defined(__MACH__)
	#include <sys/types.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif defined(__BEOS__)
	#include <sys/inttypes.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif (defined(_MSC_VER) || defined(__BORLANDC__)) && (!defined(__MSDOS__))
	typedef unsigned __int32 ISTDUINT32;
	typedef __int32 ISTDINT32;
#elif defined(__GNUC__)
	#include <stdint.h>
	typedef uint32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#else 
	typedef unsigned long ISTDUINT32; 
	typedef long ISTDINT32;
#endif
#endif


//=====================================================================
// Integer Definition
//=====================================================================
#ifndef __IINT8_DEFINED
#define __IINT8_DEFINED
typedef char IINT8;
#endif

#ifndef __IUINT8_DEFINED
#define __IUINT8_DEFINED
typedef unsigned char IUINT8;
#endif

#ifndef __IUINT16_DEFINED
#define __IUINT16_DEFINED
typedef unsigned short IUINT16;
#endif

#ifndef __IINT16_DEFINED
#define __IINT16_DEFINED
typedef short IINT16;
#endif

#ifndef __IINT32_DEFINED
#define __IINT32_DEFINED
typedef ISTDINT32 IINT32;
#endif

#ifndef __IUINT32_DEFINED
#define __IUINT32_DEFINED
typedef ISTDUINT32 IUINT32;
#endif

#ifndef __IINT64_DEFINED
#define __IINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64 IINT64;
#else
typedef long long IINT64;
#endif
#endif

#ifndef __IUINT64_DEFINED
#define __IUINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef unsigned __int64 IUINT64;
#else
typedef unsigned long long IUINT64;
#endif
#endif

#ifndef INLINE
#if defined(__GNUC__)

#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1))
#define INLINE         __inline__ __attribute__((always_inline))
#else
#define INLINE         __inline__
#endif

#elif (defined(_MSC_VER) || defined(__BORLANDC__) || defined(__WATCOMC__))
#define INLINE __inline
#else
#define INLINE 
#endif
#endif

#if (!defined(__cplusplus)) && (!defined(inline))
#define inline INLINE
#endif

//=====================================================================
// QUEUE DEFINITION                                                  
//=====================================================================
#ifndef __IQUEUE_DEF__
#define __IQUEUE_DEF__

struct IQUEUEHEAD {
	struct IQUEUEHEAD *next, *prev;
};

typedef struct IQUEUEHEAD iqueue_head;


//---------------------------------------------------------------------
// queue init                                                         
//---------------------------------------------------------------------
#define IQUEUE_HEAD_INIT(name) { &(name), &(name) }
#define IQUEUE_HEAD(name) \
	struct IQUEUEHEAD name = IQUEUE_HEAD_INIT(name)

#define IQUEUE_INIT(ptr) ( \
	(ptr)->next = (ptr), (ptr)->prev = (ptr))

#define IOFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define ICONTAINEROF(ptr, type, member) ( \
		(type*)( ((char*)((type*)ptr)) - IOFFSETOF(type, member)) )

#define IQUEUE_ENTRY(ptr, type, member) ICONTAINEROF(ptr, type, member)


//---------------------------------------------------------------------
// queue operation                     
//---------------------------------------------------------------------
#define IQUEUE_ADD(node, head) ( \
	(node)->prev = (head), (node)->next = (head)->next, \
	(head)->next->prev = (node), (head)->next = (node))

#define IQUEUE_ADD_TAIL(node, head) ( \
	(node)->prev = (head)->prev, (node)->next = (head), \
	(head)->prev->next = (node), (head)->prev = (node))

#define IQUEUE_DEL_BETWEEN(p, n) ((n)->prev = (p), (p)->next = (n))

#define IQUEUE_DEL(entry) (\
	(entry)->next->prev = (entry)->prev, \
	(entry)->prev->next = (entry)->next, \
	(entry)->next = 0, (entry)->prev = 0)

#define IQUEUE_DEL_INIT(entry) do { \
	IQUEUE_DEL(entry); IQUEUE_INIT(entry); } while (0)

#define IQUEUE_IS_EMPTY(entry) ((entry) == (entry)->next)

#define iqueue_init		IQUEUE_INIT
#define iqueue_entry	IQUEUE_ENTRY
#define iqueue_add		IQUEUE_ADD
#define iqueue_add_tail	IQUEUE_ADD_TAIL
#define iqueue_del		IQUEUE_DEL
#define iqueue_del_init	IQUEUE_DEL_INIT
#define iqueue_is_empty IQUEUE_IS_EMPTY

#define IQUEUE_FOREACH(iterator, head, TYPE, MEMBER) \
	for ((iterator) = iqueue_entry((head)->next, TYPE, MEMBER); \
		&((iterator)->MEMBER) != (head); \
		(iterator) = iqueue_entry((iterator)->MEMBER.next, TYPE, MEMBER))

#define iqueue_foreach(iterator, head, TYPE, MEMBER) \
	IQUEUE_FOREACH(iterator, head, TYPE, MEMBER)

#define iqueue_foreach_entry(pos, head) \
	for( (pos) = (head)->next; (pos) != (head) ; (pos) = (pos)->next )
	

#define __iqueue_splice(list, head) do {	\
		iqueue_head *first = (list)->next, *last = (list)->prev; \
		iqueue_head *at = (head)->next; \
		(first)->prev = (head), (head)->next = (first);		\
		(last)->next = (at), (at)->prev = (last); }	while (0)

#define iqueue_splice(list, head) do { \
	if (!iqueue_is_empty(list)) __iqueue_splice(list, head); } while (0)

#define iqueue_splice_init(list, head) do {	\
	iqueue_splice(list, head);	iqueue_init(list); } while (0)


#ifdef _MSC_VER
#pragma warning(disable:4311)
#pragma warning(disable:4312)
#pragma warning(disable:4996)
#endif

#endif


//---------------------------------------------------------------------
// BYTE ORDER & ALIGNMENT
//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
    #ifdef _BIG_ENDIAN_
        #if _BIG_ENDIAN_
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #if defined(__hppa__) || \
            defined(__m68k__) || defined(mc68000) || defined(_M_M68K) || \
            (defined(__MIPS__) && defined(__MIPSEB__)) || \
            defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
            defined(__sparc__) || defined(__powerpc__) || \
            defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #define IWORDS_BIG_ENDIAN  0
    #endif
#endif

#ifndef IWORDS_MUST_ALIGN
	#if defined(__i386__) || defined(__i386) || defined(_i386_)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(_M_IX86) || defined(_X86_) || defined(__x86_64__)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(__amd64) || defined(__amd64__)
		#define IWORDS_MUST_ALIGN 0
	#else
		#define IWORDS_MUST_ALIGN 1
	#endif
#endif

#define RUDP_OVERHEAD        24
#define RUDP_DEFMTU          1472
#define RUDP_MAXMTU          1472
#define RUDP_WNDSIZE         1024
#define RUDP_FASTRESEND      8

#define RUDP_NOTIFY_FAIL     0x01
#define RUDP_NOTIFY_SUCC     0x02
#define RUDP_NOTIFY_NEXT     0x04
#define RUDP_NOTIFY_BREAK    0x08
#define RUDP_NOTIFY_CLOSE    0x10

typedef struct IKCPSEG  IKCPSEG;
typedef struct IKCPCB   ikcpcb;

//=====================================================================
// SEGMENT
//=====================================================================
struct IKCPSEG
{
	struct IQUEUEHEAD node;
	ikcpcb *kcp;
	IUINT32 crtime;
	IINT32  refcnt;
	IUINT32 conv;
	IUINT32 cmd;
	IUINT32 frg;
	IUINT32 wnd;
	IUINT32 ts;
	IUINT32 sn;
	IUINT32 una;
	IUINT32 len;
	IUINT32 resendts;
	IUINT32 rto;
	IUINT32 fastack;
	IUINT32 xmit;
	char data[1];
};

//---------------------------------------------------------------------
// IKCPCB
//---------------------------------------------------------------------
struct IKCPCB
{
	IUINT32 conv, mask, maxmtu, mtu, mss, loss;
	IUINT32 snd_una, snd_nxt, rcv_nxt;
	IUINT32 ssthresh;
	IINT32 rx_rttval, rx_srtt, rx_rto, rx_minrto;
	IUINT32 snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
	IUINT32 current, interval, xmit;
	IUINT32 sendtime, recvtime, breaktime;
	IUINT64 rcv_total, rcv_succ, snd_total, snd_first, snd_succ;
	IUINT32 ts_flushseg, ts_flushack;
	IUINT32 nrcv_buf, nsnd_buf;
	IUINT32 nrcv_que, nsnd_que;
	IUINT32 nodelay;
	IUINT32 ts_probe, probe_wait;
	IUINT32 dead_link, incr;
	struct IQUEUEHEAD snd_queue;
	struct IQUEUEHEAD rcv_queue;
	struct IQUEUEHEAD snd_buf;
	struct IQUEUEHEAD rcv_buf;
	IUINT32 *acklist;
	IUINT32 ackblock, ackcount, ackpos;
	int ackagain;
	IUINT32 acksn, ackts;
	void *user;
	//char *buffer;
	int snd_timeout;
	int fastresend;
	int fastlimit;
	int nocwnd, stream;
	int logmask;
	IUINT32 ack_una;
	IKCPSEG **snd_bufsn, **rcv_bufsn;
	pthread_mutex_t rcv_lck, snd_lck;
	int ntftype;
	int (*output)(const char *buf, int len, struct IKCPCB *kcp, void *user);
	int (*notify)(int cmd, IKCPSEG *seg, struct IKCPCB *kcp, void *user);
	void (*writelog)(const char *log, struct IKCPCB *kcp, void *user);
};

#define IKCP_LOG_OUTPUT         0x00000001
#define IKCP_LOG_INPUT          0x00000002
#define IKCP_LOG_SEND           0x00000004
#define IKCP_LOG_RECV           0x00000008
#define IKCP_LOG_IN_DATA        0x00000010
#define IKCP_LOG_IN_ACK         0x00000020
#define IKCP_LOG_IN_PROBE       0x00000040
#define IKCP_LOG_IN_WINS        0x00000080
#define IKCP_LOG_OUT_DATA       0x00000100
#define IKCP_LOG_OUT_ACK        0x00000200
#define IKCP_LOG_OUT_PROBE      0x00000400
#define IKCP_LOG_OUT_WINS       0x00000800
#define IKCP_LOG_FLUSH          0x00001000
#define IKCP_LOG_RESEND         0x00002000
#define IKCP_LOG_ERROR          0x00004000
#define IKCP_LOG_TRACE          0x00008000
#define IKCP_LOG_BREAK          0x00010000
#define IKCP_LOG_ALL            0xFFFFFFFF

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// interface
//---------------------------------------------------------------------

// create a new kcp control object, 'conv' must equal in two endpoint
// from the same connection. 'user' will be passed to the output callback
// output callback can be setup like this: 'kcp->output = my_udp_output'
ikcpcb* ikcp_create(IUINT32 conv, IUINT32 mask, void *user, IUINT32 current);

// release kcp control object
void ikcp_release(ikcpcb *kcp);

// set output callback, which will be invoked by kcp
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len, 
	ikcpcb *kcp, void *user));

// set notify callback, which will be invoked by kcp
void ikcp_setnotify(ikcpcb *kcp, int (*notify)(int cmd, IKCPSEG *seg, 
	ikcpcb *kcp, void *user));

// user/upper level recv: returns size, returns below zero for EAGAIN
int ikcp_recv(ikcpcb *kcp, char *buffer, int size);

// user/upper level send, return available buffer for next time, below zero for error
int ikcp_send(ikcpcb *kcp, const char *data, int len, IUINT32 current);

int ikcp_clearsend(ikcpcb *kcp, const char *newdata, int len, IUINT32 current,
	int (*cmpseg)(IKCPSEG *seg, const char *newdata, int len));

// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//IINT32 ikcp_update(ikcpcb *kcp, IUINT32 current);

// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//IUINT32 ikcp_check(ikcpcb *kcp, IUINT32 current);

// when you received a low level packet (eg. UDP packet), call it
int ikcp_input(ikcpcb *kcp, const char *data, int size, IUINT32 current);

// flush pending ack, timer with kcp->interval
IINT32 ikcp_flushack(ikcpcb *kcp, IUINT32 current, int ackfast);

// flush pending data, timer with kcp->interval
IINT32 ikcp_flushseg(ikcpcb *kcp, IUINT32 current);

// check the size of next message in the recv queue
int ikcp_peeksize(ikcpcb *kcp);

// change MTU size, default is 1400
int ikcp_setmtu(ikcpcb *kcp, IUINT16 mtu);

// set maximum window size: sndwnd=32, rcvwnd=32 by default
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd);

// buffer available for next send, return >0: available, <=0: buffer still full
int ikcp_cansend(const ikcpcb *kcp);

// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
// nodelay: 0:disable(default), 1:enable
// interval: internal update timer interval in millisec, default is 100ms 
// resend: 0:disable fast resend(default), 1:enable fast resend
// nc: 0:normal congestion control(default), 1:disable congestion control
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc);

// write log
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...);

// setup allocator
void ikcp_allocator(void* (*new_malloc)(size_t, const char *, int),
	void* (*new_realloc)(void*, size_t, const char *, int), void(*new_free)(void*, const char *, int));

// read conv
IUINT32 ikcp_getconv(const void *ptr);

int ikcp_rstcmd(char *ptr, IUINT32 conv);
int ikcp_chkrst(const char *ptr);

int ikcp_oobcmd(char *ptr, IUINT32 conv, const char *data, int len);
int ikcp_chkoob(const char *ptr);

void ikcp_segment_delete(ikcpcb *kcp, struct IKCPSEG *seg);

IINT32 ikcp_idletime(ikcpcb *kcp);
int ikcp_broken(ikcpcb *kcp);

#ifdef __cplusplus
}
#endif

#endif


