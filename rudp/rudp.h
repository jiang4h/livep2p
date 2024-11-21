#ifndef _RUDP_H_
#define _RUDP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "btype.h"
#include "rudpsess.h"
#include "rudppeer.h"
#include "rudpsock.h"

#define RUDP_NOTRUDP_DATA     0x20001	
#define RUDP_RUDP_DATA	      0x20002

typedef enum rudp_notify_cmd_ {
	RUDP_NOTIFY_UNDEF = -1,
	RUDP_NOTIFY_GET_DATATYPE,
	RUDP_NOTIFY_SENDREQ_BUSY,
	RUDP_NOTIFY_SENDBUF_FULL,
	RUDP_NOTIFY_SEND_OK,
} rudp_notify_cmd_t;

enum rudp_err {
	RUDP_CODE_ERR_OK = 0,
	RUDP_CODE_ERR_UNKNOWN = -1,
	RUDP_CODE_ERR_NOT_RECV = -2,
	RUDP_CODE_ERR_REQ_BUSY = -3,
	RUDP_CODE_ERR_CON_FAILED = -4,
	RUDP_CODE_ERR_NOT_RUDP = -5,
	RUDP_CODE_ERR_MSG_ALLOC_FAILED = -6,
	RUDP_CODE_ERR_MSG_CREATE_FAILED = -7,
	RUDP_CODE_ERR_MSG_PACK_FAILED = -8,
	RUDP_CODE_ERR_MSG_LEN_TOOLARGE = -9,
	RUDP_CODE_ERR_ACK_DUP = -10,
	RUDP_CODE_ERR_ACK_MSG = -11,
	RUDP_CODE_ERR_PAYLOAD_DUP = -12,
	RUDP_CODE_ERR_UNKNOWN_CMD = -13,
	RUDP_CODE_ERR_FUNC_PARAM_ERR = -14,
	RUDP_CODE_ERR_NOT_SEND = -15,
	RUDP_CODE_ERR_ADD_MSG_FAILED = -16,
	RUDP_CODE_ERR_CON_NOT_EXIST = -17,
	RUDP_CODE_ERR_CON_REQ_DISABLE = -18,

	RUDP_CODE_ERR_BUF_FULL = -9999
};

#define	__DBG__   0
#define RUDP_ERR_BUF_FULL  RUDP_CODE_ERR_BUF_FULL

int rudp_init();
void rudp_cleanup();

void *rudp_newsock(rudpworker_pool_t *wp, const char *ip, short port, void *arg,
		fn_recvcb *recvcb, fn_notifycb *notifycb, fn_closecb *closecb, fn_destroycb *destroycb);
int rudp_sendto(void *rudpsock, char *data, int len, struct sockaddr *addr, void *arg);
void rudp_closesock(void *rudpsock);

int rudp_closeconn(void *rudpsock, struct sockaddr *addr);
int rudp_recvrate(void *rudpsock, struct sockaddr *addr);
int rudp_sendrate(void *rudpsock, struct sockaddr *addr);
int rudp_conrtt(void *rudpsock, struct sockaddr *addr);

#ifdef __cplusplus
}
#endif
#endif
