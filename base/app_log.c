#include "app_log.h"
#include <time.h>
#include <stdarg.h>

int _app_log_level = LOG_DEBUG; //LOG_INFO LOG_DEBUG;
app_log_t _applog = { 0 };
const char _log_name[] = "livep2p";
int _app_log_stdout = 1;
int _app_log_keepmax = 7;

void app_log_removefile(app_log_t* plog)
{
	char curpath[MAX_BASEPATH] = { 0 };
	int len = getcurpath(curpath, sizeof(curpath));
	uint32_t logIds[1000] = { 0 };
	uint32_t rmIds[2000] = { 0 };
	int i = 0, imin = 0, rmNum = 0, logNum = _app_log_keepmax;
	const char* filename = NULL;
	char filepath[MAX_BASEPATH];

	if (logNum > 1000) logNum = 1000;
	else if (logNum <= 0) logNum = 1;

#ifdef WIN32
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAA findData;

	snprintf(filepath, sizeof(filepath), "%s%s.*.log", curpath, plog->name);
	hFind = FindFirstFileA(filepath, &findData);
	if (hFind == INVALID_HANDLE_VALUE) return;
#else
	DIR* dp = opendir(curpath);
	struct dirent* entry;
	if (dp == NULL) return;
#endif

	len = strlen(plog->name);
#ifdef _WIN32
	do {
		filename = findData.cFileName;
#else
	while ((entry = readdir(dp)) != NULL) {
		filename = entry->d_name;
#endif
		if (strlen(filename) != (size_t)len + 13 ||
			filename[len] != '.' ||
			strncasecmp(filename, plog->name, len) ||
			strcasecmp(filename + len + 9, ".log"))
			continue;

		uint32_t findId = atoi(filename + len + 1);
		uint32_t minId = 0;

		for (i = 0; i < logNum; i++) {
			if (minId == 0 || logIds[i] < minId) {
				imin = i;
				minId = logIds[i];
			}
			if (logIds[i] == 0) {
				logIds[i] = findId;
				break;
			}
		}
		if (minId > 0 && minId != findId) {
			if (minId > findId) {
				if (rmNum < 2000) rmIds[rmNum++] = findId;
			}
			else {
				logIds[imin] = findId;
				if (rmNum < 2000) rmIds[rmNum++] = minId;
			}
		}
#ifdef _WIN32
	} while (FindNextFileA(hFind, &findData));
	FindClose(hFind);
#else
	}
	closedir(dp);
#endif

	for (i = 0; i < rmNum; i++) {
		snprintf(filepath, sizeof(filepath), "%s%s.%08u.log", curpath, plog->name, rmIds[i]);
		remove(filepath);
	}
}

static int app_log_createfile(app_log_t *plog, time_t t)
{
	char curpath[MAX_BASEPATH];
	int n;
	struct tm *lt = localtime(&t);

	if (plog->fp != NULL && lt->tm_year * 10000 + (lt->tm_mon + 1) * 100 + lt->tm_mday == plog->timebase)
		return 0;

	if (plog->fp != NULL) {
#ifdef _WIN32
		CloseHandle(plog->fp);
#else
		fclose(plog->fp);
#endif
		app_log_removefile(plog);
	}

	n = getcurpath(curpath, sizeof(curpath));
	snprintf(curpath + n, sizeof(curpath) - n, "%s.%02d%02d%02d.log", plog->name, lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday);
#ifdef _WIN32
	plog->fp = CreateFileA(curpath, FILE_APPEND_DATA | SYNCHRONIZE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
	if (plog->fp == INVALID_HANDLE_VALUE)
		plog->fp = NULL;
#else
	plog->fp = fopen(curpath, "a");
#endif

	plog->timebase = lt->tm_year * 10000 + (lt->tm_mon + 1) * 100 + lt->tm_mday; /* YYYYMMDD */
	return 0;
}

static pthread_fn app_log_thread(void *param)
{
	app_log_t *plog = param;
	int pid = getpid();
	int readpos, writepos, len;

	pthread_mutex_lock(&plog->lock);
	while (plog->status == pid) { /* exit flag */
        if (plog->readpos >= plog->writepos)
			pthread_cond_wait(&(plog->signal), &(plog->lock));
        readpos = plog->readpos % plog->bufsize;
        len = plog->writepos - plog->readpos;
		pthread_mutex_unlock(&plog->lock);

		if (readpos + len > plog->bufsize)
            len = plog->bufsize - readpos;
        if (len > 0) {
			if (_app_log_stdout)
				v_printf(plog->name, "%.*s", len, plog->buffer + readpos);

			app_log_createfile(plog, time(NULL));
			if (plog->fp != NULL) {
#ifdef _WIN32
				WriteFile(plog->fp, plog->buffer + readpos, len, &len, NULL);
#else
				fwrite(plog->buffer + readpos, 1, len, plog->fp);
				fflush(plog->fp);
#endif
			}

			pthread_mutex_lock(&plog->lock);
			plog->readpos += len;
            readpos = plog->readpos % plog->bufsize;
            writepos = plog->writepos % plog->bufsize;
			if (readpos <= writepos) {
                plog->readpos = readpos;
                plog->writepos = writepos;
			}
        }
		else
			pthread_mutex_lock(&plog->lock);
	}
	pthread_mutex_unlock(&plog->lock);

	if (plog->fp != NULL) {
		char buffer[1024];
		struct timeval tv;
		time_t t;
		struct tm lt;

		gettimeofday(&tv, NULL);
		t = tv.tv_sec;
		localtime_r(&t, &lt);
		len = snprintf(buffer, sizeof(buffer), "%d-%02d-%02d %02d:%02d:%02d.%03d %u log thread destroyed\n",
			lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec, tv.tv_usec / 1000, gettid());
#ifdef _WIN32
		WriteFile(plog->fp, buffer, len, &len, NULL);
		CloseHandle(plog->fp);
#else
		fwrite(buffer, 1, len, plog->fp);
		fclose(plog->fp);
#endif
		plog->fp = NULL;
	}
	perror("log thread destroyed");
	return 0;
}

void app_log_init(app_log_t *plog, const char *name)
{
    long pid = getpid();
	long status;

    if (!plog) plog = &_applog;
    status = plog->status;
	if (status == pid || _sync_cas32(&plog->status, status, pid) != status)
		return;

	strxcpy(plog->name, sizeof(plog->name), name ? name : _log_name, -1);
	plog->buffer = malloc(LOG_BUFSIZE);
	plog->bufsize = LOG_BUFSIZE;
    plog->fp = NULL;
    plog->timebase = 0;
    plog->readpos = plog->writepos = 0;
	pthread_mutex_init(&plog->lock, 0);
	pthread_cond_init(&plog->signal, 0);
	pthread_create(&(plog->thread), 0, app_log_thread, (void *)plog);
}

void app_log_destroy(app_log_t *plog)
{
	if (!plog) plog = &_applog;
	pthread_mutex_lock(&plog->lock);
	plog->status = 0;
	pthread_cond_signal(&plog->signal);
	pthread_mutex_unlock(&plog->lock);

	pthread_join(plog->thread, 0);

	free(plog->buffer);
	plog->buffer = NULL;
	pthread_mutex_destroy(&plog->lock);
	pthread_cond_destroy(&plog->signal);
}

void app_log_setlevel(int loglevel)
{
	_app_log_level = loglevel;
}

int app_log_write(void *vlog, const char *buffer, int len)
{
	app_log_t *plog;
	int writepos;

	if (len < 0) len = strlen(buffer);
	if (!vlog) plog = &_applog;
	else plog = (app_log_t *)vlog;

	if (plog->status == 0)
		return 0; //not initialized

	pthread_mutex_lock(&plog->lock);
	if (len > plog->bufsize)
		len = plog->bufsize;
	if (plog->writepos + len >= plog->readpos + plog->bufsize)
		plog->readpos = plog->writepos + len - plog->bufsize + 1;
	writepos = plog->writepos % plog->bufsize;
	if (writepos + len <= plog->bufsize)
		memcpy(plog->buffer + writepos, buffer, len);
	else {
		memcpy(plog->buffer + writepos, buffer, (size_t)plog->bufsize - writepos);
		memcpy(plog->buffer, buffer + ((size_t)plog->bufsize - writepos), len - ((size_t)plog->bufsize - writepos));
	}
	plog->writepos += len;
	pthread_cond_signal(&plog->signal);
	pthread_mutex_unlock(&plog->lock);
	return len;
}

int app_log_printf(app_log_t *plog, int loglevel, const char *func, int line, const char *format, ...)
{
    char buffer[MAX_LOG];
    va_list ap;
 	struct timeval tv;
	time_t t;
	struct tm lt;
    int len;

	if (loglevel < _app_log_level || loglevel > LOG_SHUTDOWN)
		return 0;

	app_log_init(plog, _log_name);
	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
	localtime_r(&t, &lt);
	len = snprintf(buffer, sizeof(buffer), "%d-%02d-%02d %02d:%02d:%02d.%03d %u %15s[%4d] %c ",
			lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec, tv.tv_usec / 1000,
			gettid(), func, line, LOG_SYMBOLS[loglevel]);
	if (len >= 0 && len < sizeof(buffer)) {
	    va_start(ap, format);
	    len += vsnprintf(buffer + len, sizeof(buffer) - len, format, ap);
	    va_end(ap);
	}
	if (len < 0)
		return 0;
	if (len >= sizeof(buffer))
		len = sizeof(buffer) - 1;
	buffer[len++] = '\n';

    return app_log_write(plog, buffer, len);
}
