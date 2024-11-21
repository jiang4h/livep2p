#ifndef _RUDPSESS_H
#define _RUDPSESS_H

#include "btype.h"
#include "rudpstat.h"
#include "ikcp.h"
#include "uthash.h"
#include "event2/event.h"
#include "event2/event_struct.h"

#define RUDPKEY_ADDRLEN   8

#define RUDPFLAG_CLOSE   -1
#define RUDPFLAG_SEND     0
#define RUDPFLAG_RECV     1

#define RUDPSESS_TIMEOUT  120
#define RUDPCHK_INTERVAL  3000

#define RUDPCONV_START    0x80000000

#define rudptv_set(tv,ms) ((tv).tv_sec = (ms) / 1000, (tv).tv_usec=((ms) % 1000) * 1000, &tv)

//conv: [type:1][server:25][client:6]
#define CONV_TYPE(conv) ((conv) & 0x80000000)
#define CONV_PEERTYPE(conv) (((conv) & 0x80000000) == 0 ? 0x80000000 : 0)
#define CONV_PEERMASK(conv) (((conv) & 0x80000000) == 0 ? 0x7FFFFFC0 : 0x0000003F)
#define CONV_PEERSESSID(conv) ((conv) & CONV_PEERMASK(conv))
#define CONV_MYMASK(conv) (((conv) & 0x80000000) == 0 ? 0x0000003F : 0x7FFFFFC0)
#define CONV_MYSESSID(conv) ((conv) & CONV_MYMASK(conv))
#define CONV_NEWSESSID(type,cseq,sseq) (((type) == 0) ? ((++(cseq)) & 0x0000003F) : (((++(sseq)) & 0x01FFFFFF) << 6))

typedef struct rudpsession_s rudpsession_t;

struct rudpsession_s
{
	uint32_t refcnt;
	uint32_t peersessid;
	uint32_t mysessid;
	ikcpcb *kcp;
	struct event segtimer;
	struct event acktimer;
	uint32_t chktime;
	rudpstat_t stat;
	char *data;
	void *rudppeer;
	DLIST_handle(rudpsession_t) lhsess;
	void *rudpsock;
	UT_hash_handle hhsess;
	int closing;
};

int rudpsess_ref(rudpsession_t *session);
int rudpsess_unref(rudpsession_t *session);
void rudpsess_close(rudpsession_t *session, int external);
int rudpsess_rstcmd(rudpsession_t *session);
int rudpsess_oobcmd(rudpsession_t *session, const char *data, int len);
rudpsession_t *rudpsess_get(void *rudpsock, 
	struct sockaddr *peeraddr, uint32_t peerconv, uint32_t curtime, int flag);
int rudpsess_send(rudpsession_t *session, const char *buf, int len, uint32_t curtime);
int rudpsess_isvalid(rudpsession_t *session);
int rudpsess_cansend(rudpsession_t *session);
uint32_t rudpsess_rto(rudpsession_t *session);
int rudpsess_sendrate(rudpsession_t *session);
int rudpsess_recvrate(rudpsession_t *session);

#endif