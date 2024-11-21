#ifndef _APP_LOG_H
#define _APP_LOG_H

#include "btype.h"

typedef struct app_log_s app_log_t;

#define LOG_SYMBOLS  " TDINWECS"
#define LOG_TRACE    1  // Messages indicating function-calling sequence
#define LOG_DEBUG    2  // Messages that contain information normally of use only when debugging a program
#define LOG_INFO     3  // Informational messages
#define LOG_NOTICE   4  // Conditions that are not error conditions, but that may require special handling
#define LOG_WARNING  5  // Warning messages
#define LOG_ERROR    6  // Error messages
#define LOG_CRITICAL 7  // Critical conditions, such as hard device errors
#define LOG_SHUTDOWN 8  // The maximum logging priority.
#define LOG_MAX      LOG_SHUTDOWN  // The maximum logging priority.

#define LOG_BUFSIZE  (1024 * 1024)

struct app_log_s
{
    void        *fp;
    int         timebase;
    char        name[MAX_BASEPATH];
    char        *buffer;
    int         bufsize;
    int         readpos;
    int         writepos;
	long        status;
	pthread_mutex_t lock;
    pthread_cond_t  signal;
    pthread_t       thread;
};

#ifdef __cplusplus
extern "C"
{
#endif

extern int _app_log_level;
extern app_log_t _applog;
extern int _app_log_stdout;

void app_log_init(app_log_t *plog, const char *filepath);
void app_log_destroy(app_log_t *plog);
void app_log_setlevel(int loglevel);
int app_log_write(void *vlog, const char *buffer, int len);
int app_log_printf (app_log_t *plog, int loglevel, const char *func, int line,  const char *format, ...);

#ifdef __cplusplus
}
#endif

#define app_log_exit() app_log_destroy(&_applog)

#define APP_LOG(loglevel, fmt, ...) \
	(loglevel >= _app_log_level) ? app_log_printf(&_applog, loglevel, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__) : 0

#define log_debug(fmt, ...)  \
	(LOG_DEBUG >= _app_log_level) ? app_log_printf(&_applog, LOG_DEBUG, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__) : 0

#define log_info(fmt, ...)  \
	(LOG_INFO >= _app_log_level) ? app_log_printf(&_applog, LOG_INFO, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__) : 0

#define log_warn(fmt, ...)  \
	(LOG_WARNING >= _app_log_level) ? app_log_printf(&_applog,LOG_WARNING,  __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__) : 0

#define log_error(fmt, ...)  \
	(LOG_ERROR >= _app_log_level) ? app_log_printf(&_applog, LOG_ERROR, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__) : 0

#endif
