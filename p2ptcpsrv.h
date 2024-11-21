#ifndef _P2P_TCPSRV_H
#define _P2P_TCPSRV_H

#include "btype.h"
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

typedef struct p2ptcpcli_s   p2ptcpcli_t;
typedef struct p2ptcpsrv_s   p2ptcpsrv_t;

struct p2ptcpcli_s
{
	uint64_t packseq;
	char *buf;
	int len;
	p2ptcpsrv_t *tcpsrv;
	struct bufferevent *bev;
	DLIST_handle(p2ptcpcli_t) lhcli;
};

struct p2ptcpsrv_s
{
	void *p2psched;
	char ip[16];
	uint16_t port;
	uint64_t recvtime;
	struct event_base *evbase;
	struct evconnlistener *evlistener;
	pthread_t tid;
	DLIST_head(p2ptcpcli_t) ltcli;
};

p2ptcpsrv_t *p2ptcpsrv_new(void *p2psched, const char *ip, uint16_t port);
void p2ptcpsrv_destroy(p2ptcpsrv_t *tcpsrv);

#endif
