#include "rudpworker.h"
#include "app_log.h"

#define RUDPWORKER_MAX_RUNTIME  5
#define RUDPWORKER_MAX_WORKER   100000

static pthread_fn rudpworker_run(void *param)
{
	rudpworker_t *worker = (rudpworker_t *)param;
	rudpworker_set_t *ws = worker->ws;
	rudpworker_pool_t *wp = ws->wp;
	rudpworker_job_t *job;
	int wk_exit_flag = 0;

	while (ws->exit_flag == 0 && wk_exit_flag == 0) {
		pthread_mutex_lock(&ws->lock);
		job = DLIST_HEAD(ws->ltjob);
		if (job == NULL) {
			pthread_cond_wait(&(ws->signal), &(ws->lock));
			job = DLIST_HEAD(ws->ltjob);
			if (job == NULL) {
				pthread_mutex_unlock(&ws->lock);
				continue;
			}
		}
		assert(job->param > 0x10000);
		DLIST_DEL(lhjob, ws->ltjob, job);
		worker->status = RUDPWORKER_BUSY;
		ws->runworker++;
		pthread_mutex_unlock(&ws->lock);

		ws->runtime = time(NULL);
		assert(job->param > 0x10000);
		job->func(job->param);

		pthread_mutex_lock(&ws->lock);
		worker->status = RUDPWORKER_IDLE;
		ws->jobnum--;
		ws->runworker--;
		if (worker->intern && ws->jobnum < ws->workernum) {
			wk_exit_flag = 1;
		}
		if (ws->jobfreenum <= 16) {
			DLIST_ADD(lhjob, ws->ltjobfree, job);
			ws->jobfreenum++;
			pthread_mutex_unlock(&ws->lock);
		}
		else {
			pthread_mutex_unlock(&ws->lock);
			kfree(job);
		}
	}

	pthread_mutex_lock(&ws->lock);
	DLIST_DEL(lhworker, ws->ltworker, worker);
	ws->workernum--;
	if (ws->workernum == 0) {
		pthread_mutex_unlock(&ws->lock);

		pthread_mutex_destroy(&ws->lock);
		pthread_cond_destroy(&ws->signal);
		kfree(ws);
		if (_sync_add32(&wp->wksetnum, -1) == 1) {
			log_info("rudpworker pool destroyed\n");
			kfree(wp);
		}
	}
	else 
		pthread_mutex_unlock(&ws->lock);

	log_debug("%p worker end, to %d, jobnum %d/%d", ws, ws->workernum, ws->jobnum, ws->runworker);
	return kfree(worker), 0;
}

static int rudpworker_addworker(rudpworker_set_t *ws, int intern)
{
	rudpworker_t *worker = kcalloc(1, sizeof(rudpworker_t));
	worker->intern = intern;
	worker->status = RUDPWORKER_IDLE;
	worker->ws = ws;

	pthread_mutex_lock(&ws->lock);
	DLIST_ADD_TAIL(lhworker, ws->ltworker, worker);
	pthread_mutex_unlock(&ws->lock);

	if (pthread_create(&(worker->tid), 0, rudpworker_run, worker) == 0)
		return 0; //success
	
	pthread_mutex_lock(&ws->lock);
	ws->workernum--;
	DLIST_DEL(lhworker, ws->ltworker, worker);
	pthread_mutex_unlock(&ws->lock);
	kfree(worker);
	return -1; //fail
}

int rudpworker_addjob(rudpworker_pool_t *wp, void(*func)(void *), void *param, int rudp)
{
	rudpworker_set_t *ws = (rudp != 0 && wp->wksetnum > 1) ? wp->wkset[1] : wp->wkset[0];
	rudpworker_job_t *job;
	int addworker;

	pthread_mutex_lock(&ws->lock);
	job = DLIST_HEAD(ws->ltjobfree);
	if (job != NULL) {
		DLIST_DEL(lhjob, ws->ltjobfree, job);
		ws->jobfreenum--;
	}
	pthread_mutex_unlock(&ws->lock);
	if (job == NULL) 
		job = kalloc(sizeof(rudpworker_job_t));
	job->func = func;
	job->param = param;
	job->createtime = getcurtime_ms();

	//log_debug("job %lu %p %p", job->createtime, job->func, job->param);

	pthread_mutex_lock(&ws->lock);
	assert(job->param > 0x10000);
	DLIST_ADD_TAIL(lhjob, ws->ltjob, job);
	ws->jobnum++;
	pthread_cond_signal(&ws->signal);

	if (ws->workernum >= RUDPWORKER_MAX_WORKER 
		|| ws->runworker < ws->workernum 
		|| time(NULL) < ws->runtime + RUDPWORKER_MAX_RUNTIME)
		addworker = 0;
	else {
		addworker = RUDPWORKER_MAX_WORKER - ws->workernum;
		if (addworker > ws->workernum)
			addworker = ws->workernum;
		ws->workernum += addworker;
	}
	pthread_mutex_unlock(&ws->lock);

	if (addworker > 0) {
		log_debug("%p workernum add %d, to %d, jobnum %d/%d", ws, addworker, ws->workernum, ws->jobnum, ws->runworker);
	}

	while (--addworker >= 0)
		rudpworker_addworker(ws, 1);
	return 0;
}

rudpworker_pool_t *rudpworker_new(int appnum, int rudpnum, void *data)
{
	rudpworker_pool_t *wp = kcalloc(1, sizeof(rudpworker_pool_t));
	rudpworker_set_t *ws;
	int wknum[2] = { appnum , rudpnum };
	int i, workernum;

	wp->data = data;
	for (i = 0; i < 2; i++) {
		ws = kcalloc(1, sizeof(rudpworker_set_t));
		pthread_mutex_init(&ws->lock, 0);
		pthread_cond_init(&ws->signal, 0);

		ws->workernum = workernum = wknum[i];
		while (--workernum >= 0)
			rudpworker_addworker(ws, 0);

		if (ws->workernum <= 0) {
			pthread_mutex_destroy(&ws->lock);
			pthread_cond_destroy(&ws->signal);
			kfree(ws);
			break;
		}
		wp->wkset[i] = ws;
		_sync_add32(&wp->wksetnum, 1);
	}

	if (wp->wksetnum <= 0) {
		log_info("rudpworker pool destroyed: %d\n", wp->wksetnum);
		kfree(wp);
		wp = NULL;
	}
	return wp;
}

void rudpworker_destroy(rudpworker_pool_t * wp)
{
	rudpworker_set_t *ws;
	int i;

	for (i = 0; i < wp->wksetnum; i++) {
		ws = wp->wkset[i];
		pthread_mutex_lock(&ws->lock);
		ws->exit_flag = 1;
		pthread_cond_broadcast(&ws->signal);
		pthread_mutex_unlock(&ws->lock);
	}
}
