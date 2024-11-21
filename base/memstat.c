#include "btype.h"
#include "app_log.h"

#define MEM_TRACE_SIZE_LIMIT (1024 * 1024 * 1024)
#define MEM_TRACE_SIZE_WARN  (100 * 1024 * 1024)
#define MEM_TRACE_SUM_WARN   (2 * 1024 * 1024 * 1024ll)

#define MEM_LOG_FILE    "memstat.log"
#define MEM_GUARD       "mgua"

#define mem_errlog(_fmt, ...) do { \
    FILE *_fp = fopen(MEM_LOG_FILE, "a"); \
    if (_fp != NULL) { \
        struct timeval _tv; \
        time_t _ts; \
        struct tm _lt; \
        gettimeofday(&_tv, NULL); \
        _ts = _tv.tv_sec; \
        localtime_r(&_ts, &_lt); \
        fprintf(_fp, "%d-%02d-%02d %02d:%02d:%02d.%03d tid:%u " _fmt "\n", \
            _lt.tm_year + 1900, _lt.tm_mon + 1, _lt.tm_mday, _lt.tm_hour, _lt.tm_min, _lt.tm_sec, _tv.tv_usec / 1000, \
            gettid(), ##__VA_ARGS__); \
        fclose(_fp); \
    } \
} while (0)

typedef struct {
	int size;
	int count;
	int next;
} mcount_t;

typedef struct {
	int64_t sum;
	int64_t count;
	mcount_t *stat;
	int *stat_idx;
	int stat_num;
	int64_t callnum;
	pthread_mutex_t lck;
	pthread_cond_t cond;
	pthread_t tid;
} mstat_t;

static mstat_t *gmstat = NULL;
static long     gstatus = 0;

static pthread_fn memstat_thread(void *param)
{
	mstat_t *mstat = (mstat_t *)param;
	mcount_t *stat2;
	int64_t count2;
	int64_t sum2;
	int64_t callnum2;
	struct timespec ts;
	int i;

	if (mstat == NULL) return 0;

	while (gstatus != 0)
	{
		pthread_cond_ms2timespec(&ts, 3000);
		pthread_mutex_lock(&mstat->lck);
		pthread_cond_timedwait(&mstat->cond, &mstat->lck, &ts);
		stat2 = (mcount_t *)calloc(mstat->stat_num, sizeof(mcount_t));
		memcpy(stat2, mstat->stat, sizeof(mcount_t) * mstat->stat_num);
		count2 = mstat->count;
		sum2 = mstat->sum;
		callnum2 = mstat->callnum;
		pthread_mutex_unlock(&mstat->lck);

		for (i = 0; i < mstat->stat_num; ++i) {
			if (stat2[i].size == 0 || stat2[i].count == 0)
				continue;
			log_debug("[memstat] i %d, size %u count %d next %d\n", i, stat2[i].size, stat2[i].count, stat2[i].next);
		}
		log_debug("[memstat] count %lld, sum %lld, callnum %lld \n", count2, sum2, callnum2);
		free(stat2);
	}

	return 0;
}

void mstat_cleanup()
{
	mstat_t *mstat = gmstat;
	gstatus = 0;
	gmstat = NULL;
	if (mstat != NULL) {
		if (mstat->tid != 0) {
			pthread_mutex_lock(&mstat->lck);
			pthread_cond_signal(&mstat->cond);
			pthread_mutex_unlock(&mstat->lck);
			pthread_join(mstat->tid, NULL);
		}
		free(mstat->stat);
		free(mstat->stat_idx);
		pthread_mutex_destroy(&mstat->lck);
		pthread_cond_destroy(&mstat->cond);
		free(mstat);
	}
}

int mstat_init(int stat_num)
{
#if !(_DBG_STAT)
	return 0;
#else
	long pid = getpid();
	long status;
	mstat_t *mstat;
	int i;

	status = gstatus;
	if (status == pid || _sync_cas32(&gstatus, status, pid) != status) return 0;

	if (stat_num <= 0) stat_num = 10000;

	mstat = (mstat_t *)calloc(1, sizeof(mstat_t));
	mstat->stat = (mcount_t *)calloc(stat_num, sizeof(mcount_t));
	mstat->stat_idx = (int *)calloc(stat_num, sizeof(int));
	mstat->stat_num = stat_num;
	pthread_mutex_init(&mstat->lck, 0);
	pthread_cond_init(&mstat->cond, 0);
	for (i = 0; i < stat_num - 1; i++)
		mstat->stat[i].next = i + 1;

	gmstat = mstat;
	return pthread_create(&gmstat->tid, 0, memstat_thread, gmstat);
#endif
}

static int mstat_stat(int size, int inc)
{
	int i, j, k, count = 0;
	mstat_t *mstat;

	if (gmstat == NULL) {
		mstat_init(0);
		if (gmstat == NULL) return 0;
	}
	mstat = gmstat;

	pthread_mutex_lock(&mstat->lck);
	k = size % mstat->stat_num;
	i = mstat->stat_idx[k];
	j = 0;

	if (i == 0)	{
		i = mstat->stat[0].next;
		if (i > 0) {
			mstat->stat[0].next = mstat->stat[i].next;
			mstat->stat[i].next = 0;
			mstat->stat_idx[k] = i;
		}
	} else {
		while (i > 0 && mstat->stat[i].size != size) {
			j = i;
			i = mstat->stat[i].next;
		}
		if (i == 0) {
			i = mstat->stat[0].next;
			if (i > 0) {
				mstat->stat[0].next = mstat->stat[i].next;
				mstat->stat[i].next = mstat->stat[j].next;
				mstat->stat[j].next = i;
			}
		}
	}
	if (i > 0) {
		mstat->stat[i].size = size;
		if (inc > 0)
			mstat->stat[i].count++;
		else
			mstat->stat[i].count--;
		if (mstat->stat[i].count == 0) {
			mstat->stat[i].size = 0;
			if (j == 0)
				mstat->stat_idx[k] = mstat->stat[i].next;
			else
				mstat->stat[j].next = mstat->stat[i].next;
			mstat->stat[i].next = mstat->stat[0].next;
			mstat->stat[0].next = i;
		}
		count = mstat->stat[i].count;
	}

	if (inc > 0) {
		mstat->count++;
		mstat->sum += size;
	} else {
		mstat->count--;
		mstat->sum -= size;
	}

	mstat->callnum++;
	pthread_mutex_unlock(&mstat->lck);
	
	return count;
}

void* mstat_malloc(size_t size, const char *file, int line)
{
	if (size <= 0 || size >= MEM_TRACE_SIZE_LIMIT) {
		mem_errlog("mem error: kalloc invalid size, size:%lld, line:%d, file:%s",
			size, line, file);
		return NULL;
	}

	if (size >= MEM_TRACE_SIZE_WARN) {
		mem_errlog("mem warn: kalloc big size, size:%lld, line:%d, file:%s",
			size, line, file);
	}

	char *p = malloc(size + sizeof(int) * 3);
	if (p == NULL) {
		mem_errlog("mem error: kalloc null, size:%lld, line:%d, file:%s",
			size, line, file);
		return NULL;
	}

	int count = mstat_stat((int)size, 1);
	if (count % (MEM_TRACE_SUM_WARN / size) == 0) {
		mem_errlog("mem warn: kalloc too many, count:%ld, size:%lld, line:%d, file:%s",
			count, size, line, file);
	}

	*(int *)(p) = size;
	*(int *)((char *)p + sizeof(int)) = *(int *)MEM_GUARD;
	*(int *)((char *)p + sizeof(int) * 2 + size) = *(int *)MEM_GUARD;
	return (char *)p + sizeof(int) * 2;
}

void *mstat_zalloc(size_t size, const char *file, int line)
{
	char *p = mstat_malloc(size, file, line);
	if (p != NULL)
		memset(p, 0, size);
	return p;
}

void* mstat_realloc(void *ptr, size_t size, const char *file, int line)
{
	if (ptr != NULL) {
		ptr = (char *)ptr - sizeof(int) * 2;
		mstat_stat(*(int *)ptr, -1);

		if (*(int *)ptr <= 0 || *(int *)ptr >= MEM_TRACE_SIZE_LIMIT) {
			mem_errlog("mem error: freed before krealloc, ptr:%p, size:%ld, line:%d, file:%s",
				ptr, *(int *)ptr, line, file);
			return NULL;
		}

		if (*(int *)((char *)ptr + sizeof(int)) != *(int *)MEM_GUARD) {
			mem_errlog("mem error: invalid before krealloc, ptr:%p, size:%ld, line:%d, file:%s",
				ptr, *(int *)ptr, line, file);
			return NULL;
		}
		
		if (*(int *)((char *)ptr + sizeof(int) * 2 + *(int *)ptr) != *(int *)MEM_GUARD) {
			mem_errlog("mem error: overflow before krealloc, ptr:%p, size:%ld, line:%d, file:%s",
				ptr, *(int *)ptr, line, file);
			return NULL;
		}
	}

	if (size <= 0 || size >= MEM_TRACE_SIZE_LIMIT) {
		mem_errlog("mem error: krealloc invalid size, size:%lld, line:%d, file:%s",
			size, line, file);
		return NULL;
	}
	
	if (size >= MEM_TRACE_SIZE_WARN) {
		mem_errlog("mem warn: krealloc big size, size:%lld, line:%d, file:%s",
			size, line, file);
	}

	ptr = realloc(ptr, size + sizeof(int) * 3);
	if (ptr == NULL) {
		mem_errlog("mem error: krealloc null, size:%lld, line:%d, file:%s",
			size, line, file);
		return ptr;
	}

	int count = mstat_stat((int)size, 1);
	if (count % (MEM_TRACE_SUM_WARN / size) == 0) {
		mem_errlog("mem warn: krealloc too many, count:%ld, size:%lld, line:%d, file:%s",
			count, size, line, file);
	}

	*(int *)ptr = size;
	*(int *)((char *)ptr + sizeof(int)) = *(int *)MEM_GUARD;
	*(int *)((char *)ptr + sizeof(int) * 2 + size) = *(int *)MEM_GUARD;
	return (char *)ptr + sizeof(int) * 2;
}

void mstat_free(void *ptr, const char *file, int line)
{
	if (ptr != NULL) {
		ptr = (char *)ptr - sizeof(int) * 2;
		if (*(int *)ptr <= 0 || *(int *)ptr >= MEM_TRACE_SIZE_LIMIT) {
			mem_errlog("mem error: freed before kfree, ptr:%p, size:%ld, line:%d, file:%s",
				ptr, *(int *)ptr, line, file);
			return;
		}

		if (*(int *)((char *)ptr + sizeof(int)) != *(int *)MEM_GUARD) {
			mem_errlog("mem error: invalid before kfree, ptr:%p, size:%ld, line:%d, file:%s",
				ptr, *(int *)ptr, line, file);
			return;
		}
		
		if (*(int *)((char *)ptr + sizeof(int) * 2 + *(int *)ptr) != *(int *)MEM_GUARD) {
			mem_errlog("mem error: overflow before kfree, ptr:%p, size:%ld, line:%d, file:%s",
				ptr, *(int *)ptr, line, file);
			return;
		}
		
		mstat_stat(*(int *)ptr, -1);
		*(int *)ptr = -*(int *)ptr;
		free(ptr);
	}
}
