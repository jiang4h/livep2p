#ifndef __RUDP__H
#define __RUDP__H

#include "rudpstat.h"
#include "rudpsess.h"
#include "rudppeer.h"
#include "rudpworker.h"

typedef struct rudpbuffer_s rudpbuffer_t;
typedef struct rudpsocket_s rudpsocket_t;

typedef int fn_oobcb(rudpsession_t *session, char *buf, int len, int offset, void *data);
typedef int fn_recvcb(rudpsession_t *session, char *buf, int len, void *data);
typedef int fn_notifycb(rudpsession_t *session, char *buf, int len, int ack, void *data);
typedef int fn_closecb(rudpsession_t *session, void *data);
typedef int fn_destroycb(rudpsocket_t *rudp);

#ifdef _WIN32
#define WINSOCK_IOCP 0
#if WINSOCK_IOCP
typedef struct _PER_IO_OPERATION_DATA
{
	OVERLAPPED Overlapped;
	WSABUF DataBuff;

	rudpbuffer_t *rcvbuf;
} PER_IO_OPERATION_DATA, *LPPER_IO_OPERATION_DATA;
int rudp_iocp_add(rudppeer_t *peer);
#endif
#endif

struct rudpbuffer_s
{
	char buf[RUDP_MAXMTU];
	int len;
	uint32_t refcnt;
	struct sockaddr addr;
	rudpsocket_t *rudpsock;
	rudpsession_t *rudpsess;
	rudpbuffer_t *next;
};

struct rudpsocket_s
{
	uint32_t refcnt;
	rudpworker_pool_t *wp;
	//bindings
	char ip[16];
	unsigned short port;
	//event objects
	struct event_base *evbase;
#if WINSOCK_IOCP
	HANDLE hIoCP;
#endif
	SOCKET sockfd;
	struct event evsock;
	//kcp parameters
	int sesslen;
	int sessidle;
	int maxmtu;
	int interval;
	int minrto;
	int fastresend;
	int wndsize;
	int xmitmax;
	int sndtimeout;
	int ntftype;
	//session callbacks
	uint32_t cseq, sseq;
	fn_oobcb *oobcb;
	fn_recvcb *recvcb;
	fn_notifycb *notifycb;
	fn_closecb *closecb;
	fn_destroycb *destroycb;
	char *data;
	//statistics
	rudpstat_t stat;
	struct event chktimer;
	//sessions
	rudppeer_t *htpeer;
	rudpsession_t *htsess;
	pthread_mutex_t ht_lck;
	//buffers
	rudpbuffer_t *buffree;
	uint32_t bufusenum;
	uint32_t buffreenum;
	pthread_mutex_t buf_lck;
	//status
	int closing;
};

int rudpsock_init();
void rudpsock_cleanup();

int rudpsock_ref(rudpsocket_t *rudp);
int rudpsock_unref(rudpsocket_t *rudp);
void rudpsock_close(rudpsocket_t *rudp);
void rudpsock_setoobcb(rudpsocket_t *rudp, fn_oobcb *oobcb);
void rudpsock_recvjob1(void *rudpbuf);
rudpsocket_t *rudpsock_new(rudpworker_pool_t *wp, const char *ip, short port, int sesslen, int sessidle,
	int maxmtu, int interval, int minrto, int fastresend, int wndsize, int xmitmax, int sndtimeout, int ntftype,
	fn_recvcb *recvcb, fn_notifycb *notifycb, fn_closecb *closecb, fn_destroycb *destroycb, void *data);
rudpsession_t *rudpsock_connect(rudpsocket_t *rudp, uint32_t saddr, uint16_t port);
int rudpsock_sendrate(rudpsocket_t *rudp);
int rudpsock_recvrate(rudpsocket_t *rudp);
int rudpsock_failcnt(rudpsocket_t *rudp);
int rudpsock_sessnum(rudpsocket_t *rudp);

int rudpbuffer_ref(void *buf);
int rudpbuffer_unref(rudpbuffer_t *buf);
void *rudpbuffer_alloc(rudpsocket_t *rudp, rudpsession_t *session);
void rudpbuffer_free(void *buf);

#endif
