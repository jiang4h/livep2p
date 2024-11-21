#ifndef _RUDPSTAT_H
#define _RUDPSTAT_H

#include "btype.h"

#define RUDPSTAT_INTERVAL   30000

typedef struct rudpstat_s rudpstat_t;

struct rudpstat_s
{
	uint32_t createtime;
	uint32_t bgntime;
	uint64_t recvbytes;
	uint64_t sendbytes;
	uint32_t recvcnt;
	uint32_t sendcnt;
	uint32_t failcnt;
	uint32_t recvrate;
	uint32_t sendrate;
	uint64_t total_recvbytes;
	uint64_t total_sendbytes;
	uint64_t total_recvcnt;
	uint64_t total_sendcnt;
	uint64_t total_failcnt;
	int32_t  srvdiff;
	pthread_mutex_t lock;
};

void rudpstat_synctime(rudpstat_t *pstat, uint32_t curtime, uint32_t srvtime);
uint32_t rudpstat_srvtime(rudpstat_t *pstat, uint32_t curtime);
void rudpstat_init(rudpstat_t *pstat, uint32_t curtime);
void rudpstat_recv(rudpstat_t *pstat, uint32_t recvbytes);
void rudpstat_send(rudpstat_t *pstat, uint32_t sendbytes);
void rudpstat_fail(rudpstat_t *pstat);
void rudpstat_statis(rudpstat_t *pstat, uint32_t curtime);
void rudpstat_destroy(rudpstat_t *pstat);

#endif