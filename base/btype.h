#ifndef _APP_BTYPE_
#define _APP_BTYPE_
#ifndef _WIN32
#ifndef UNIX
#define UNIX
#endif /*UNIX*/
#else
#ifndef WINDOWS
#define WINDOWS
#endif /*WINDOWS*/
#endif /*_WIN32*/

#ifdef ANDROID
#include <android/log.h>
#define v_printf(tag, ...) __android_log_print(ANDROID_LOG_INFO, tag, __VA_ARGS__)
#endif /*ANDROID*/

#ifdef _MSTAR_ANDROID
#define LOG_TAG "WISE"
#include <utils/Log.h>
#define v_printf(tag, ...) LOGE(__VA_ARGS__)
#endif /*_MSTAR_ANDROID*/

#ifndef v_printf
#define v_printf(tag, ...) printf(__VA_ARGS__)
#endif /*v_printf*/

#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>

#ifdef UNIX
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/syscall.h>
#endif /*UNIX*/

#ifdef WINDOWS
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <setupapi.h>
#include <initguid.h>
#include <winioctl.h>
#include <process.h>
#include <windows.h>
#include <sddl.h>
#endif /*WINDOWS*/

#if defined WINDOWS
#define gettid() GetCurrentThreadId()
#elif defined ANDROID
#include <sys/syscall.h>
#define gettid() syscall(__NR_gettid)
#else
#define gettid() syscall(SYS_gettid)
#endif /*WINDOWS*/

#ifdef __cplusplus
extern "C" {
#endif
#ifndef INFINITE
#define INFINITE  0xFFFFFFFF
#endif

static inline int getcurpath(char curpath[], int size)
{
#if defined (UNIX)
	char link[256];
	char* p;

	snprintf(link, sizeof(link), "/proc/%d/exe", getpid());
	readlink(link, curpath, size);
	p = strrchr(curpath, '/');
#else // WIN32
	char* p;

	GetModuleFileNameA(NULL, curpath, size);
	p = strrchr(curpath, '\\');
#endif
	if (p) {
		*(p + 1) = '\0';
		return (int)(p - curpath + 1);
	}
	return (int)strlen(curpath);
}

static inline int getcpunum()
{
#if defined WINDOWS
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwNumberOfProcessors;
#elif defined ANDROID
	return get_nprocs_conf();
#else
	return get_nprocs_conf(); //sysconf(_SC_NPROCESSORS_CONF);
#endif
}

static inline time_t get_build_time()
{
	static time_t buildtime = 0;
	struct tm t = { 0 };
	char *p;

	if (buildtime == 0) {
		switch (__DATE__[2]) {
		case 'n': t.tm_mon = (__DATE__[1] == 'a') ? 0 : 5; break; //"Jan", "Jun"
		case 'b': t.tm_mon = 1; break; //"Feb"
		case 'r': t.tm_mon = (__DATE__[1] == 'a') ? 2 : 3; break; //"Mar", "Apr"
		case 'y': t.tm_mon = 4; break; //"May"
		case 'l': t.tm_mon = 6; break; //"Jul"
		case 'g': t.tm_mon = 7; break; //"Aug"
		case 'p': t.tm_mon = 8; break; //"Sep"
		case 't': t.tm_mon = 9; break; //"Oct"
		case 'v': t.tm_mon = 10; break; //"Nov"
		case 'c': t.tm_mon = 11; break; //"Dec"
		default: t.tm_mon = 0; break;
		}

		t.tm_mday = strtol(__DATE__ + 4, &p, 10);
		t.tm_year = strtol(p + 1, &p, 10) - 1900;

		t.tm_hour = strtol(__TIME__, &p, 10);
		t.tm_min = strtol(p + 1, &p, 10);
		t.tm_sec = strtol(p + 1, &p, 10);

		buildtime = mktime(&t);
	}
	
	return buildtime;
}

static inline uint64_t getcurtime_us()
{
#ifdef WINDOWS
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	return ((uint64_t)ft.dwLowDateTime
		+ (((uint64_t)ft.dwHighDateTime) << 32)
		- 116444736000000000uLL) / 10;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec) * 1000 * 1000 + tv.tv_usec;
#endif
}

#define time_us2sec(_us_) ((uint32_t)(((_us_) / 1000000) & 0xFFFFFFFFul))
#define time_us2ms(_us_) ((uint32_t)(((_us_) / 1000) & 0xFFFFFFFFul))
#define getcurtime_ms() time_us2ms(getcurtime_us())

static inline void pthread_cond_ms2timespec(struct timespec *ts, int ms)
{
	if (ts == NULL)
		return;
#ifdef 	WINDOWS
	ts->tv_sec = (ms / 1000);
	ts->tv_nsec = (ms % 1000) * 1000000;
#else
	struct timeval tv;
	
	gettimeofday(&tv, NULL);
	ts->tv_sec = tv.tv_sec + ms / 1000;
	ts->tv_nsec = tv.tv_usec * 1000 + (ms % 1000) * 1000000;
#endif
}

static inline int pthread_cond_timespec2ms(const struct timespec *ts)
{
	if (ts == NULL)
		return INFINITE;
#ifdef 	WINDOWS
	int ms = (int)(ts->tv_sec * 1000) + (ts->tv_nsec / 1000000);
#else
	struct timeval tv;
	
	gettimeofday(&tv, NULL);
	int ms = (int)(ts->tv_sec - tv.tv_sec) * 1000 + (int)(ts->tv_nsec / 1000000 - tv.tv_usec / 1000);
#endif
	return ms < 0 ? 0 : ms;
}

#ifndef min
#define min(x,y)  ((x) <= (y)?(x):(y))
#endif
#ifndef max
#define max(x,y)  ((x) >= (y)?(x):(y))
#endif

#ifdef UNIX
#define CRITICAL_SECTION   pthread_mutex_t
#define InitializeCriticalSection(cs)  pthread_mutex_init(cs,NULL)
#define DeleteCriticalSection(cs)  pthread_mutex_destroy(cs,NULL)
#define EnterCriticalSection(cs)   pthread_mutex_lock(cs)
#define LeaveCriticalSection(cs)   pthread_mutex_unlock(cs)

#define isBigEndian()   ((*(unsigned short *)("KE") >> 8) == 'K')
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#define rol2(x,n)( ((x) << (n)) | ((x) >> (64-(n))) )
#define swap2(b) ( ((uint16_t)(b)<<8)|((uint16_t)(b)>>8) )
#define swap4(b) ( (rol((uint32_t)(b), 24) & 0xff00ff00) | (rol((uint32_t)(b), 8) & 0x00ff00ff) )
#define swap8(b) ( (rol2((uint64_t)(b),8 )&0x000000FF000000FFULL) | \
                   (rol2((uint64_t)(b),24)&0x0000FF000000FF00ULL) | \
                   (rol2((uint64_t)(b),40)&0x00FF000000FF0000ULL) | \
                   (rol2((uint64_t)(b),56)&0xFF000000FF000000ULL) )
#define htonll(b) ( isBigEndian()?(b):swap8(b) )
#define ntohll(b) ( isBigEndian()?(b):swap8(b) )

#define TRUE   1
#define FALSE  0
#define BOOL   int

#define _strnicmp strncasecmp
#define SLEEP(x) usleep((x)*1000)

#define SOCKET int
#define INVALID_SOCKET   -1
#define SOCKET_ERROR     -1
#define closesocket       close
#define sockerr           errno
#define strsockerr        strerror
#define SOCK_ERR_EAGAIN  (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR || errno==EINPROGRESS)

#define OutputDebugString printf

#define InterlockedIncrement(pint32) __sync_add_and_fetch(pint32, 1)
#define InterlockedDecrement(pint32) __sync_sub_and_fetch(pint32, 1)

#define pthread_fn void *

#define pthread_rdlock_lock(a)      pthread_rwlock_rdlock(a)
#define pthread_rdlock_unlock(a)    pthread_rwlock_unlock(a)
#define pthread_wrlock_lock(a)      pthread_rwlock_wrlock(a)
#define pthread_wrlock_unlock(a)    pthread_rwlock_unlock(a)

#define _sync_add32(pint32,inc)    __sync_fetch_and_add(pint32,inc)
#define _sync_add64(pint64,inc)    __sync_fetch_and_add(pint64,inc)
#define _sync_cas32(pint32,oldval,newval) __sync_val_compare_and_swap(pint32,oldval,newval)
#define _sync_or32(pint32,mask)    __sync_fetch_and_or(pint32,mask)
#define _sync_and32(pint32,mask)   __sync_fetch_and_and(pint32,mask)
#define _sync_or8(pint8,mask)      __sync_fetch_and_or(pint8,mask)
#define _sync_and8(pint8,mask)     __sync_fetch_and_and(pint8,mask)
#endif /* end if UNIX */

#ifdef WINDOWS
typedef int       socklen_t;
#define sockerr   WSAGetLastError()

static inline char *strsockerr(int err)
{
  __declspec(thread) static char msgbuf[256] = { 0 };   // for a message up to 255 bytes.

  msgbuf[0] = '\0';
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS/*flags*/,
    NULL/*lpsource*/, err/*message id*/, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)/*languageid*/,
    msgbuf/*output buffer*/, sizeof(msgbuf)/*size of msgbuf, bytes*/, NULL/*va_list of arguments*/);
  return msgbuf;
}

#define SOCK_ERR_EAGAIN  (WSAGetLastError()==WSAEWOULDBLOCK)

#define pthread_t HANDLE
#define pthread_fn unsigned int __stdcall
#define pthread_create(tid,attr,func,arg) (*(tid)=(HANDLE)_beginthreadex(attr,0,func, arg,0,NULL),*(tid)?0:-1)
#define pthread_self()         GetCurrentThread()
#define pthread_equal(t1,t2)  (GetThreadId(t1)==GetThreadId(t2))
#define pthread_join(tid,v)   (WaitForSingleObject(tid,INFINITE),CloseHandle(tid),0)
#define pthread_detach(tid)   (CloseHandle(tid),0)

#define pthread_mutex_t               CRITICAL_SECTION
#define pthread_mutex_unlock(a)       LeaveCriticalSection(a)
#define pthread_mutex_lock(a)         EnterCriticalSection(a)
#define pthread_mutex_init(a,b)       InitializeCriticalSection(a)
#define pthread_mutex_destroy(a)      DeleteCriticalSection(a)

#define pthread_cond_t                CONDITION_VARIABLE
#define pthread_cond_init(cond,arg)   InitializeConditionVariable(cond)
#define pthread_cond_signal(cond)     WakeConditionVariable(cond)
#define pthread_cond_broadcast(cond)  WakeAllConditionVariable(cond)
#define pthread_cond_wait(cond,mutex) (!SleepConditionVariableCS(cond, mutex, INFINITE))
#define pthread_cond_timedwait(cond,mutex,abstime) (!SleepConditionVariableCS(cond,mutex,pthread_cond_timespec2ms(abstime)))
#define pthread_cond_destroy(cond)    (void)(cond)

#define pthread_rwlock_t              SRWLOCK
#define pthread_rwlock_init(a,b)      InitializeSRWLock(a)
#define pthread_rdlock_lock(a)        AcquireSRWLockShared(a)
#define pthread_rdlock_unlock(a)      ReleaseSRWLockShared(a)
#define pthread_wrlock_lock(a)        AcquireSRWLockExclusive(a)
#define pthread_wrlock_unlock(a)      ReleaseSRWLockExclusive(a)
#define pthread_rwlock_destroy(a)     (void)(a)

#define SLEEP Sleep

#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#define srandom      srand
#define random       rand
#define atoll		_atoi64
#define localtime_r(a,b) (localtime_s(b,a),b)

#define MSG_NOSIGNAL 0

#define realpath(r,a) _fullpath(a,r,MAX_BASEPATH)

typedef LONG(CALLBACK* API_NtSetTimerResolution)(IN ULONG DesiredTime, IN BOOLEAN SetResolution, OUT PULONG ActualTime);

static int SetTimerResolution(int us)
{
	HMODULE h = LoadLibrary(TEXT("ntdll.dll"));
	if (h == NULL) return -1;

	API_NtSetTimerResolution NtSetTimerResolution = (API_NtSetTimerResolution)GetProcAddress(h, "NtSetTimerResolution");
	if (NtSetTimerResolution == NULL) return -1;

	ULONG actualResolution = 0;
	NtSetTimerResolution(us * 10, TRUE, &actualResolution);
	FreeLibrary(h);
	return actualResolution;
}

struct timezone {
	int tz_minuteswest;     /* minutes west of Greenwich */
	int tz_dsttime;         /* type of DST correction */
};

static inline int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned long long us;
	static int once = 0;

	(void *)tz; //unreferenced parameter
	if (once == 0) {
		once = 1;
		SetTimerResolution(1000);
	}

	GetSystemTimeAsFileTime(&ft);
	us = ((unsigned long long)ft.dwLowDateTime
		+ (((unsigned long long)ft.dwHighDateTime) << 32)
		- 116444736000000000uLL) / 10;
	tv->tv_sec = (long)(us / 1000000);
	tv->tv_usec = (long)(us % 1000000);
    return (0);
}

static inline const char *strcasestr(const char *text, const char *pattern)
{
	if (!text || !pattern)
		return NULL;

	int m = (int)strlen(pattern);
	int n = (int)strlen(text);
	int next[256];
	int i, j, k;

	if (n < m)
		return NULL;

	for (i = 0; i < 256; i++)
		next[i] = m + 1;
	for (i = 0; i < m; i++)
		next[(unsigned char)toupper(pattern[i])] = m - i;

	i = 0;
	while (1)
	{
		j = i, k = 0;
		while (j < n && k < m && toupper(text[j]) == toupper(pattern[k]))
			j++, k++;

		if (k == m)
			return text + i;

		if (i + m >= n)
			break;
		i += next[(unsigned char)toupper(text[i + m])];
	}
	return NULL;
}

#pragma warning(disable : 4996)
#pragma warning(disable : 4244)
#pragma warning(disable : 4133)
#pragma warning(disable : 4267)

#define _sync_add32(pint32,inc)    InterlockedExchangeAdd(pint32,inc)
#define _sync_add64(pint64,inc)    InterlockedExchangeAdd64(pint64,inc)
#define _sync_cas32(pint32,oldval,newval) InterlockedCompareExchange(pint32,newval,oldval)
#define _sync_or32(pint32,mask)    InterlockedOr(pint32,mask)
#define _sync_and32(pint32,mask)   InterlockedAnd(pint32,mask)
#define _sync_or8(pint8,mask)      InterlockedOr8(pint8,mask)
#define _sync_and8(pint8,mask)     InterlockedAnd8(pint8,mask)
#endif /* endif WINDOWS */

#define MAX_MTU      1472
#define MAX_PACK     1448
#define MAX_BUF      65536
#define MAX_HOST     256
#define MAX_PORT     10
#define MAX_BASEPATH 1024
#define MAX_FULLPATH 4096
#define MAX_FILE     256
#define MAX_PARAM    1024
#define MAX_URL      2048
#define MAX_HEAD     8192

#define MAX_CONTYPE  128
#define MAX_PKG      512
#define MAX_LOG      3072

static inline int strxcpy(char *dst_str, int dst_size, const char *src_str, int src_len)
{
	if (dst_size > 1) {
		if (src_len < 0) {
			src_len = src_str ? strlen(src_str) : 0;
		}
		if (src_len > 0) {
			if (src_len >= dst_size) {
				src_len = dst_size - 1;
			}
			memcpy(dst_str, src_str, src_len);
			dst_str[src_len] = '\0';
			return src_len;
		}
		else {
			dst_str[0] = '\0';
		}
	}
	else if (dst_size > 0) {
		dst_str[0] = '\0';
	}
	return 0;
}

static inline int strxcat(char *dst_str, int dst_size, const char *src_str, int src_len)
{
	int _i = strlen(dst_str);
	if (dst_size > _i + 1) {
		if (src_len < 0) {
			src_len = src_str ? strlen(src_str) : 0;
		}
		if (src_len > 0) {
			if (_i + src_len >= dst_size) {
				src_len = dst_size - (_i + 1);
			}
			memcpy(dst_str + _i, src_str, src_len);
			dst_str[_i + src_len] = '\0';
			return src_len;
		}
	}
	return 0;
}

#define memxcpy(dst_buf, dst_size, src_bytes, src_len) \
	memcpy(dst_buf, src_bytes, (src_len) <= (dst_size) ? (src_len) : (dst_size))

#define _DBG_STAT 0

int mstat_init(int stat_num);
void mstat_cleanup();

#if _DBG_STAT
void* mstat_malloc(size_t size, const char *file, int line);
void *mstat_zalloc(size_t size, const char *file, int line);
void* mstat_realloc(void *ptr, size_t size, const char *file, int line);
void  mstat_free(void *ptr, const char *file, int line);

#define kmalloc(size) mstat_malloc(size, __FILE__, __LINE__)
#define kalloc kmalloc
#define kzalloc(size) mstat_zalloc(size, __FILE__, __LINE__)
#define krealloc(ptr, size) mstat_realloc(ptr, size, __FILE__, __LINE__)
#define kcalloc(count, size) mstat_zalloc(size * count, __FILE__, __LINE__)
#define kfree(ptr) mstat_free(ptr, __FILE__, __LINE__)
#else
#define kmalloc malloc
#define kalloc kmalloc

static inline void *kzalloc(size_t size) {
	void *p = malloc(size);
	if (p != NULL)
		memset(p, 0, size);
	return p;
}

#define krealloc realloc
#define kcalloc calloc
#define kfree free
#endif

#define DLIST_head(type) struct {\
	type         *prev; \
	type         *next; \
    unsigned int count; \
}

#define DLIST_handle(type) struct {\
	type    *prev; \
	type    *next; \
}

#define DLIST_INIT(head) (head).prev=(head).next=NULL,(head).count=0

#define DLIST_COPY(dst,src) (dst).prev=(src).prev,(dst).next=(src).next,(dst).count=(src).count

#define DLIST_COUNT(head) (head).count

#define DLIST_CONCAT(lh,dst,src) do { \
	if ((src).next == NULL) break; \
	if ((dst).prev != NULL) (dst).prev->lh.next = (src).next; \
	else (dst).next = (src).next; \
	(src).next->lh.prev = (dst).prev; \
	(dst).prev = (src).prev; \
	(dst).count += (src).count; \
} while (0)

#define DLIST_ADD(lh, head, node) do { \
	(node)->lh.next = (head).next; (node)->lh.prev = NULL; \
	if ((head).next != NULL) (head).next->lh.prev = (node); \
	(head).next = (node); \
	if ((head).prev == NULL) (head).prev = (node); \
	(head).count++; \
} while (0)

#define DLIST_ADD_TAIL(lh, head, node) do { \
	(node)->lh.prev = (head).prev; (node)->lh.next = NULL; \
	if ((head).prev != NULL) (head).prev->lh.next = (node); \
	(head).prev = (node); \
	if ((head).next == NULL) (head).next = (node); \
	(head).count++; \
} while (0)

#define DLIST_INSERT(lh, head, lead, node) do { \
	(node)->lh.prev = (lead); (node)->lh.next = (lead)->lh.next; \
	if ((lead)->lh.next != NULL) (lead)->lh.next->lh.prev = (node); \
	else (head).prev = (node); \
	(lead)->lh.next = (node); (head).count++; \
} while (0)

#define DLIST_DEL(lh, head, node) do { \
	if ((node)->lh.prev != NULL) (node)->lh.prev->lh.next = (node)->lh.next; \
	else (head).next = (node)->lh.next; \
	if ((node)->lh.next != NULL) (node)->lh.next->lh.prev = (node)->lh.prev; \
	else (head).prev = (node)->lh.prev; \
	(head).count--; \
} while (0)

#define DLIST_MOVE(lh, head, node) do { \
	if ((head).next != node) { \
		(node)->lh.prev->lh.next = (node)->lh.next; \
		if ((node)->lh.next != NULL) (node)->lh.next->lh.prev = (node)->lh.prev; \
		else (head).prev = (node)->lh.prev; \
		(node)->lh.next = (head).next; (node)->lh.prev = NULL; \
		(head).next->lh.prev = (node); \
		(head).next = (node); \
	} \
} while (0)

#define DLIST_MOVE_TAIL(lh, head, node) do { \
	if ((head).prev != node) { \
		(node)->lh.next->lh.prev = (node)->lh.prev; \
		if ((node)->lh.prev != NULL) (node)->lh.prev->lh.next = (node)->lh.next; \
		else (head).next = (node)->lh.next; \
		(node)->lh.prev = (head).prev; (node)->lh.next = NULL; \
		(head).prev->lh.next = (node); \
		(head).prev = (node); \
	} \
} while (0)

#define DLIST_IS_EMPTY(head) ((head).next == NULL)

#define DLIST_HEAD(head) (head).next
#define DLIST_TAIL(head) (head).prev
#define DLIST_NEXT(lh, node) (node)->lh.next
#define DLIST_PREV(lh, node) (node)->lh.prev

#define DLIST_FOREACH(lh, head, pos, tmp) \
	for ((pos) = (head).next, (tmp) = (pos) ? (pos)->lh.next : NULL; \
		(pos) != NULL; (pos) = (tmp), (tmp) = (pos) ? (pos)->lh.next : NULL)

#ifdef __cplusplus
}
#endif

#endif
