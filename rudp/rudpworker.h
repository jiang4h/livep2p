#ifndef _RUDPWORKER_H
#define _RUDPWORKER_H

#include "btype.h"
#include "event2/event.h"
#include "event2/event_struct.h"

typedef struct rudpworker_s       rudpworker_t;
typedef struct rudpworker_pool_s  rudpworker_pool_t;

struct rudpworker_s {
	pthread_t tid;
	uint32_t runtime;
	struct event_base *evbase;
	struct event evtimer;
	rudpworker_pool_t *wp;
};

struct rudpworker_pool_s {
	int32_t workernum;
	uint32_t workerpos;
	rudpworker_t *workers;
	void *owner;
};

rudpworker_pool_t* rudpworker_new(int threadnum, void *owner);
struct event_base *rudpworker_evbase(rudpworker_pool_t *wp);
void rudpworker_destroy(rudpworker_pool_t *wp);

#endif
