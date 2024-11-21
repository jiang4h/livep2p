#ifndef _P2P_HTTPSRV_H
#define _P2P_HTTPSRV_H

#include "btype.h"
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#define HTTPCLI_PLAYTS    1
#define HTTPCLI_PLAYM3U8  2
#define HTTPCLI_PLAYSEG   3

typedef struct p2phttpcli_s   p2phttpcli_t;
typedef struct p2phttpsrv_s   p2phttpsrv_t;

struct p2phttpcli_s
{
	p2phttpsrv_t *httpsrv;
	struct bufferevent *bev;
	char   buf[MAX_HEAD];
	int    len;
	int    type;
	void *p2psched;
	uint64_t packid;
	int sent;
	struct event evtimer;
	DLIST_handle(p2phttpcli_t) lhcli;
};

struct p2phttpsrv_s
{
	void          *p2pmgmt;
	void          *p2psched; //last sched opened
	char           ip[16];
	uint16_t       port;
	struct event_base     *evbase;
	struct evconnlistener *evlistener;
	pthread_t      tid;
	DLIST_head(p2phttpcli_t) ltcli;
};

p2phttpsrv_t *p2phttpsrv_new(void *p2pmgmt, const char *ip, uint16_t port);
void p2phttpsrv_destroy(p2phttpsrv_t *tcpsrv);


#endif
