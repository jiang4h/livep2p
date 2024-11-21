#ifndef _PROBE_H
#define _PROBE_H

#include "btype.h"
#include "event2/event.h"
#include "event2/event_struct.h"

#define PROBE_IDLE    0x01
#define PROBE_BUSY    0x02

typedef struct probe_obj_s     probe_obj_t;
typedef struct probe_job_s     probe_job_t;
typedef struct probe_worker_s  probe_worker_t;
typedef struct probe_s         probe_t;

struct probe_obj_s {
	probe_t   *pcore;

};

struct probe_job_s {
	int        cmd;
	void      *para;
	int        para_cplen;
	void     (*cb)(void*);
	void      *cbpara;
	uint32_t   createtime;
	char       ext[16];
	DLIST_handle(probe_job_t) lhjob;
};

struct probe_worker_s {
	probe_t   *pcore;
	pthread_t  tid;
	int        intern;
	int        status;
	DLIST_handle(probe_worker_t) lhworker;
};

struct probe_s {
	uint32_t  workernum;
	uint32_t  jobnum;
	uint32_t  jobfreenum;
	uint32_t  runtime;
	int       runworker;
	int       exit_flag;
	DLIST_head(probe_worker_t) ltworker;
	DLIST_head(probe_job_t) ltjob;
	DLIST_head(probe_job_t) ltjobfree;
	pthread_mutex_t lock;
	pthread_cond_t signal;
	pthread_t tid;
	struct event_base *evbase;
};

probe_t* probe_new(int threadnum, int threadmax, void *data, int forkone);
void probe_destroy(probe_t *pcore);
int probe_timer(probe_t *pcore, int waitms, int cmd, void *para, int para_cplen, void(*cb)(void *), void *cbpara);


#endif
