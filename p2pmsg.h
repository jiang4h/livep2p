#ifndef _P2P_MSG_H_
#define _P2P_MSG_H_

#include "btype.h"

#define P2P_CMD_BASE               0
#define P2P_CMD_ACK_BASE           0x80
#define P2P_CMD_REQ_MAX            0x7F

#define P2P_CMD_REQ_LOGIN          (P2P_CMD_BASE + 1)
#define P2P_CMD_ACK_LOGIN          (P2P_CMD_ACK_BASE | P2P_CMD_REQ_LOGIN)

#define P2P_CMD_REQ_HELLO          (P2P_CMD_BASE + 2)
#define P2P_CMD_ACK_HELLO          (P2P_CMD_ACK_BASE | P2P_CMD_REQ_HELLO)

#define P2P_CMD_REQ_BLOCK_ANY      (P2P_CMD_BASE + 3)
#define P2P_CMD_ACK_PACK_ANY       (P2P_CMD_ACK_BASE | P2P_CMD_REQ_BLOCK_ANY)

#define P2P_CMD_REQ_BLOCK          (P2P_CMD_BASE + 4)
#define P2P_CMD_ACK_PACK           (P2P_CMD_ACK_BASE | P2P_CMD_REQ_BLOCK)

#define GET_CMD_TYPE(buf)          (*(uint8_t*)(buf))
#define GET_CMD_SEQ(buf)           (*((uint8_t*)(buf) + 1))
#define GET_CMD_REQTYPE(cmdtype)   ((cmdtype) & P2P_CMD_REQ_MAX)
#define GET_CMD_ACKTYPE(cmdtype)   ((cmdtype) | P2P_CMD_ACK_BASE)
#define IS_CMD_ACK(cmdtype)        (((cmdtype) & P2P_CMD_ACK_BASE) == 0 ? 0 : 1)

#define BITS_LEN(bitsize)          (((bitsize) + 7) >> 3)
#define BITS_POS(bitpos)           ((bitpos) >> 3)
#define BITS_OFFSET(bitpos)        (7 - ((bitpos) & 0x07))
#define BITS_MASK(bitpos)          (0x01 << BITS_OFFSET(bitpos))
#define BITS_SET(bits,bitpos,fill) ((fill ? _sync_or8(&bits[BITS_POS(bitpos)], BITS_MASK(bitpos)) : \
                                            _sync_and8(&bits[BITS_POS(bitpos)], ~BITS_MASK(bitpos))) \
                                            & BITS_MASK(bitpos))
#define BITS_GET(bits,bitpos)      (bits[BITS_POS(bitpos)] & BITS_MASK(bitpos))

#define MAX_GETPEERNUM             10

#pragma pack(1)

typedef struct p2pmsg_cmd_s
{
	uint8_t       type;
	uint8_t       seq;            //req/ack pair matching
	uint32_t      cid;
} p2pmsg_cmd_t;

typedef struct p2pmsg_param_s
{
	uint16_t      len;
	uint16_t      mtu;
	uint8_t       interval;
	uint8_t       minrto;
	uint8_t       fastresend;
	uint8_t       xmitmax;
	uint16_t      sndtimeout;
	uint16_t      wndsize;
	uint16_t      maxidle;
	uint16_t      packsize;       //byte num of a pack
	uint16_t      blocksize;      //pack num of a block
	uint16_t      blocknum;       //block num of a buf
	uint16_t      packskip;       //pack num between read and write 
	uint16_t      trkinter;
	uint16_t      blktimeout;
	uint16_t      hlotimeout;
	uint8_t       maxlowers;
	uint8_t       maxlowerc;
} p2pmsg_param_t;

typedef struct p2pmsg_peer_s
{
	uint64_t      uid;
	uint32_t      logintime;      //peer last login time(s)
	uint32_t      lanip;          //inet_addr(ip)
	uint16_t      lanport;      
	uint32_t      wanip;          //inet_addr(ip)
	uint16_t      wanport;
	uint32_t      buildtime;      //peer build time(s)
} p2pmsg_peer_t;

typedef struct p2pmsg_bitmap_s    // block bitmap
{
	uint64_t  startpackid;   //start pack id of block
	uint16_t  bitsize;       //bit number of bits
	uint16_t  bitstart;      //start pack id to request
	uint8_t   *bits;         //bitmap of block, a pack per bit
} p2pmsg_bitmap_t;

typedef struct p2pcmd_req_block_any_s
{
	p2pmsg_cmd_t    cmd;
	uint64_t        uid;
	uint16_t        bitsize;
} p2pmsg_req_block_any_t;

typedef struct p2pcmd_req_block_s
{
	p2pmsg_cmd_t    cmd;
	uint64_t        uid;
	p2pmsg_bitmap_t bitmap;
} p2pmsg_req_block_t;

typedef struct p2pmsg_ack_pack_s
{	
	p2pmsg_cmd_t  cmd;
	uint64_t      uid;
	uint64_t      packid;        //pack id, init as getcurtime_us
	uint8_t       attr;          //key/reset flag 
	uint16_t      len;           //reply pack data len
	uint8_t	      *data; 	     //reply pack data
} p2pmsg_ack_pack_t, p2pmsg_pack_t;

//tracker/peer: update/hole peer
typedef struct p2pmsg_req_hello_s
{
	p2pmsg_cmd_t  cmd;
	p2pmsg_peer_t peer;
	uint64_t      dstuid;        //relay by tracker, or 0:directly
} p2pmsg_req_hello_t;

//peer:ack notify
typedef struct p2pmsg_ack_hello_s
{
	p2pmsg_cmd_t  cmd;
	p2pmsg_peer_t peer;
} p2pmsg_ack_hello_t;

//tracker: login/status
typedef struct p2pmsg_req_login_s
{
	p2pmsg_cmd_t  cmd;
	p2pmsg_peer_t peer;
	uint64_t      upperuid;      //upper uid inuse
	uint32_t      upperrate;     //upper recv rate
	uint64_t      startpackid;   //cache startpackid
	uint64_t      maxpackid;     //cache maxpackid
	uint8_t       push;          //source
	uint8_t       getpeernum;    //num of peers to get
} p2pmsg_req_login_t;

typedef struct p2pmsg_ack_login_s
{
	p2pmsg_cmd_t   cmd;
	uint64_t       uid;
	uint32_t       logintime;    //login time(s)
	uint32_t       curtime;      //current time(ms)
	uint32_t       wanip;
	uint16_t       wanport;
	p2pmsg_param_t param;
	uint8_t        peernum;
	p2pmsg_peer_t  peers[MAX_GETPEERNUM];
} p2pmsg_ack_login_t;

#pragma pack()

char* p2pmsg_cmd_encode(char *ptr, p2pmsg_cmd_t *msg);
const char* p2pmsg_cmd_decode(const char *ptr, p2pmsg_cmd_t *msg);

char* p2pmsg_param_encode(char *ptr, p2pmsg_param_t *msg);
const char* p2pmsg_param_decode(const char *ptr, p2pmsg_param_t *msg);

char* p2pmsg_peer_encode(char *ptr, p2pmsg_peer_t *msg);
const char* p2pmsg_peer_decode(const char *ptr, p2pmsg_peer_t *msg);

char* p2pmsg_bitmap_encode(char *ptr, p2pmsg_bitmap_t *msg);
const char* p2pmsg_bitmap_decode(const char *ptr, p2pmsg_bitmap_t *msg);

char* p2pmsg_req_block_any_encode(char *ptr, p2pmsg_req_block_any_t *msg);
const char* p2pmsg_req_block_any_decode(const char *ptr, p2pmsg_req_block_any_t *msg);

char* p2pmsg_req_block_encode(char *ptr, p2pmsg_req_block_t *msg);
const char* p2pmsg_req_block_decode(const char *ptr, p2pmsg_req_block_t *msg);

char* p2pmsg_pack_encode(char *ptr, p2pmsg_pack_t *msg);
const char* p2pmsg_pack_decode(const char *ptr, p2pmsg_pack_t *msg);

char* p2pmsg_req_hello_encode(char *ptr, p2pmsg_req_hello_t *msg);
const char* p2pmsg_req_hello_decode(const char *ptr, p2pmsg_req_hello_t *msg);

char* p2pmsg_ack_hello_encode(char *ptr, p2pmsg_ack_hello_t *msg);
const char* p2pmsg_ack_hello_decode(const char *ptr, p2pmsg_ack_hello_t *msg);

char* p2pmsg_req_login_encode(char *ptr, p2pmsg_req_login_t *msg);
const char* p2pmsg_req_login_decode(const char *ptr, p2pmsg_req_login_t *msg);

char* p2pmsg_ack_login_encode(char *ptr, p2pmsg_ack_login_t *msg);
const char* p2pmsg_ack_login_decode(const char *ptr, p2pmsg_ack_login_t *msg);

#endif
