#include "rudpworker.h"
#include "app_log.h"

static pthread_fn rudpworker_evloop(void *param)
{
	rudpworker_t *worker = param;
	
	event_base_dispatch(worker->evbase);
	event_base_free(worker->evbase);
	return 0;
}

static void rudpworker_timer(evutil_socket_t fd, short event, void *arg)
{
	rudpworker_t *worker = (rudpworker_t *)arg;	
	struct timeval tv = { 1, 0 };

	worker->runtime = getcurtime_ms();
	event_add(&worker->evtimer, &tv);
}

rudpworker_pool_t *rudpworker_new(int threadnum, void *owner)
{
	rudpworker_pool_t *wp;
	int i, workernum;

	workernum = getcpunum();
	if (workernum < threadnum)
		workernum = threadnum;

	wp = kcalloc(1, sizeof(rudpworker_pool_t) + workernum * sizeof(rudpworker_t));
	wp->workernum = 0;
	wp->workerpos = 0;
	wp->workers = (rudpworker_t *)(wp + 1);
	wp->owner = owner;
	for (i = 0; i < workernum; i++) {
		rudpworker_t *worker = &wp->workers[i];
		struct event_config *evcfg;
		struct timeval tv = { 1, 0 };

		evcfg = event_config_new();
		if (evcfg == NULL)
			worker->evbase = event_base_new();
		else {
			event_config_set_flag(evcfg, EVENT_BASE_FLAG_PRECISE_TIMER);
			worker->evbase = event_base_new_with_config(evcfg);
			event_config_free(evcfg);
		}
		event_assign(&worker->evtimer, worker->evbase, -1, 0, rudpworker_timer, worker);
		event_add(&worker->evtimer, &tv);

		worker->wp = wp;
		wp->workernum++;
		if (pthread_create(&(worker->tid), 0, rudpworker_evloop, worker) < 0) break;
	}
	wp->workernum = i;
	if (wp->workernum <= 0) {
		log_info("rudpworker pool create failed\n");
		return kfree(wp), NULL;
	}
	return wp;
}

struct event_base *rudpworker_evbase(rudpworker_pool_t * wp)
{
	return wp->workers[_sync_add32(&wp->workerpos, 1) % wp->workernum].evbase;
}

void rudpworker_destroy(rudpworker_pool_t * wp)
{
	int i, workernum;

	workernum = wp->workernum;
	for (i = 0; i < workernum; i++) {
		event_base_loopbreak(wp->workers[i].evbase);
		pthread_join(wp->workers[i].tid, NULL);
	}
	kfree(wp);
}
