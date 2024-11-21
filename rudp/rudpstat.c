#include "rudpstat.h"

void rudpstat_synctime(rudpstat_t *pstat, uint32_t curtime, uint32_t srvtime)
{
	pstat->srvdiff = srvtime - curtime;
}

uint32_t rudpstat_srvtime(rudpstat_t *pstat, uint32_t curtime)
{
	return curtime + pstat->srvdiff;
}

void rudpstat_init(rudpstat_t *pstat, uint32_t curtime)
{
	memset(pstat, 0, sizeof(rudpstat_t));
	pstat->createtime = pstat->bgntime = curtime;
	pthread_mutex_init(&pstat->lock, 0);
}

void rudpstat_recv(rudpstat_t *pstat, uint32_t recvbytes)
{
	pthread_mutex_lock(&pstat->lock);
	pstat->recvbytes += recvbytes;
	pstat->total_recvbytes += recvbytes;
	pstat->recvcnt++;
	pstat->total_recvcnt++;
	pthread_mutex_unlock(&pstat->lock);
}

void rudpstat_send(rudpstat_t *pstat, uint32_t sendbytes)
{
	pthread_mutex_lock(&pstat->lock);
	pstat->sendbytes += sendbytes;
	pstat->total_sendbytes += sendbytes;
	pstat->sendcnt++;
	pstat->total_sendcnt++;
	pthread_mutex_unlock(&pstat->lock);
}

void rudpstat_fail(rudpstat_t *pstat)
{
	pthread_mutex_lock(&pstat->lock);
	pstat->failcnt++;
	pstat->total_failcnt++;
	pthread_mutex_unlock(&pstat->lock);
}

void rudpstat_statis(rudpstat_t *pstat, uint32_t curtime)
{
	int32_t statms;

	pthread_mutex_lock(&pstat->lock);
	statms = curtime - pstat->bgntime;
	if (statms > 0) {
		pstat->sendrate = pstat->sendbytes * 1000 / statms;
		pstat->recvrate = pstat->recvbytes * 1000 / statms;
	}
	if (statms >= RUDPSTAT_INTERVAL) {
		pstat->sendbytes = pstat->recvbytes = 0;
		pstat->sendcnt = pstat->recvcnt = pstat->failcnt = 0;
		pstat->bgntime = curtime;
	}
	pthread_mutex_unlock(&pstat->lock);
}

void rudpstat_destroy(rudpstat_t *pstat)
{
	pthread_mutex_destroy(&pstat->lock);
}
