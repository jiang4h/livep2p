#include "p2pmsg.h"

static inline char *iter_encode8u(char *p, uint8_t c)
{
	*(uint8_t *)p = c;
	return p + 1;
}

static inline const char *iter_decode8u(const char *p, uint8_t *c)
{
	*c = *(uint8_t *)p;
	return p + 1;
}

static inline char *iter_encode16u(char *p, uint16_t w)
{
	*(uint16_t*)(p) = htons(w);
	return p + 2;
}

static inline const char *iter_decode16u(const char *p, uint16_t *w)
{
	*w = ntohs(*(const uint16_t *)p);
	return p + 2;
}

static inline char *iter_encode32u(char *p, uint32_t l)
{
	*(uint32_t *)p = htonl(l);
	return p + 4;
}

static inline const char *iter_decode32u(const char *p, uint32_t *l)
{
	*l = ntohl(*(const uint32_t *)p);
	return p + 4;
}

static inline char *iter_encode64u(char *p, uint64_t ll)
{
	*(uint64_t *)p = htonll(ll);
	return p + 8;
}

static inline const char *iter_decode64u(const char *p, uint64_t *ll)
{
	*ll = ntohll(*(const uint64_t *)p);
	return p + 8;
}

static inline char *iter_encode_bytes(char *p, uint8_t *data, int len)
{
	if (len > 0) memcpy(p, data, len);
	return p + len;
}

static inline const char *iter_decode_bytes(const char *p, uint8_t **data, int len)
{
	*data = (uint8_t *)p;
	return p + len;
}

char* p2pmsg_cmd_encode(char *ptr, p2pmsg_cmd_t *msg)
{
	ptr = iter_encode8u(ptr, msg->type);
	ptr = iter_encode8u(ptr, msg->seq);
	ptr = iter_encode32u(ptr, msg->cid);
	return ptr;
}

const char* p2pmsg_cmd_decode(const char *ptr, p2pmsg_cmd_t *msg)
{
	ptr = iter_decode8u(ptr, &msg->type);
	ptr = iter_decode8u(ptr, &msg->seq);
	ptr = iter_decode32u(ptr, &msg->cid);
	return ptr;
}

char* p2pmsg_param_encode(char *ptr, p2pmsg_param_t *msg)
{
	char *pstart = ptr;

	ptr = iter_encode16u(ptr, msg->len);
	ptr = iter_encode16u(ptr, msg->mtu);
	ptr = iter_encode8u(ptr, msg->interval);
	ptr = iter_encode8u(ptr, msg->minrto);
	ptr = iter_encode8u(ptr, msg->fastresend);
	ptr = iter_encode8u(ptr, msg->xmitmax);
	ptr = iter_encode16u(ptr, msg->sndtimeout);
	ptr = iter_encode16u(ptr, msg->wndsize);
	ptr = iter_encode16u(ptr, msg->maxidle);
	ptr = iter_encode16u(ptr, msg->packsize);
	ptr = iter_encode16u(ptr, msg->blocksize);
	ptr = iter_encode16u(ptr, msg->blocknum);
	ptr = iter_encode16u(ptr, msg->packskip);
	ptr = iter_encode16u(ptr, msg->trkinter);
	ptr = iter_encode16u(ptr, msg->blktimeout);
	ptr = iter_encode16u(ptr, msg->hlotimeout);
	ptr = iter_encode8u(ptr, msg->maxlowers);
	ptr = iter_encode8u(ptr, msg->maxlowerc);
	iter_encode16u(pstart, ptr - pstart);
	return ptr;
}

const char* p2pmsg_param_decode(const char *ptr, p2pmsg_param_t *msg)
{
	const char *pstart = ptr;

	ptr = iter_decode16u(ptr, &msg->len);
	ptr = iter_decode16u(ptr, &msg->mtu);
	ptr = iter_decode8u(ptr, &msg->interval);
	ptr = iter_decode8u(ptr, &msg->minrto);
	ptr = iter_decode8u(ptr, &msg->fastresend);
	ptr = iter_decode8u(ptr, &msg->xmitmax);
	ptr = iter_decode16u(ptr, &msg->sndtimeout);
	ptr = iter_decode16u(ptr, &msg->wndsize);
	ptr = iter_decode16u(ptr, &msg->maxidle);
	ptr = iter_decode16u(ptr, &msg->packsize);
	ptr = iter_decode16u(ptr, &msg->blocksize);
	ptr = iter_decode16u(ptr, &msg->blocknum);
	ptr = iter_decode16u(ptr, &msg->packskip);
	ptr = iter_decode16u(ptr, &msg->trkinter);
	ptr = iter_decode16u(ptr, &msg->blktimeout);
	ptr = iter_decode16u(ptr, &msg->hlotimeout);
	ptr = iter_decode8u(ptr, &msg->maxlowers);
	ptr = iter_decode8u(ptr, &msg->maxlowerc);
	return pstart + msg->len;
}

char* p2pmsg_peer_encode(char *ptr, p2pmsg_peer_t *msg)
{
	ptr = iter_encode64u(ptr, msg->uid);
	ptr = iter_encode32u(ptr, msg->logintime);
	ptr = iter_encode32u(ptr, msg->lanip);
	ptr = iter_encode16u(ptr, msg->lanport);
	ptr = iter_encode32u(ptr, msg->wanip);
	ptr = iter_encode16u(ptr, msg->wanport);
	ptr = iter_encode32u(ptr, msg->buildtime);
	return ptr;
}

const char* p2pmsg_peer_decode(const char *ptr, p2pmsg_peer_t *msg)
{
	ptr = iter_decode64u(ptr, &msg->uid);
	ptr = iter_decode32u(ptr, &msg->logintime);
	ptr = iter_decode32u(ptr, &msg->lanip);
	ptr = iter_decode16u(ptr, &msg->lanport);
	ptr = iter_decode32u(ptr, &msg->wanip);
	ptr = iter_decode16u(ptr, &msg->wanport);
	ptr = iter_decode32u(ptr, &msg->buildtime);
	return ptr;
}

char* p2pmsg_bitmap_encode(char *ptr, p2pmsg_bitmap_t *msg)
{
	ptr = iter_encode64u(ptr, msg->startpackid);
	ptr = iter_encode16u(ptr, msg->bitsize);
	ptr = iter_encode16u(ptr, msg->bitstart);
	ptr = iter_encode_bytes(ptr, msg->bits, BITS_LEN(msg->bitsize));
	return ptr;
}

const char* p2pmsg_bitmap_decode(const char *ptr, p2pmsg_bitmap_t *msg)
{
	ptr = iter_decode64u(ptr, &msg->startpackid);
	ptr = iter_decode16u(ptr, &msg->bitsize);
	ptr = iter_decode16u(ptr, &msg->bitstart);
	ptr = iter_decode_bytes(ptr, &msg->bits, BITS_LEN(msg->bitsize));
	return ptr;
}

char* p2pmsg_req_block_any_encode(char *ptr, p2pmsg_req_block_any_t *msg)
{
	ptr = p2pmsg_cmd_encode(ptr, &msg->cmd);
	ptr = iter_encode64u(ptr, msg->uid);
	ptr = iter_encode16u(ptr, msg->bitsize);
	return ptr;
}

const char* p2pmsg_req_block_any_decode(const char *ptr, p2pmsg_req_block_any_t *msg)
{
	ptr = p2pmsg_cmd_decode(ptr, &msg->cmd);
	ptr = iter_decode64u(ptr, &msg->uid);
	ptr = iter_decode16u(ptr, &msg->bitsize);
	return ptr;
}

char* p2pmsg_req_block_encode(char *ptr, p2pmsg_req_block_t *msg)
{
	ptr = p2pmsg_cmd_encode(ptr, &msg->cmd);
	ptr = iter_encode64u(ptr, msg->uid);
	ptr = p2pmsg_bitmap_encode(ptr, &msg->bitmap);
	return ptr;
}

const char* p2pmsg_req_block_decode(const char *ptr, p2pmsg_req_block_t *msg)
{
	ptr = p2pmsg_cmd_decode(ptr, &msg->cmd);
	ptr = iter_decode64u(ptr, &msg->uid);
	ptr = p2pmsg_bitmap_decode(ptr, &msg->bitmap);
	return ptr;
}

char* p2pmsg_pack_encode(char *ptr, p2pmsg_pack_t *msg)
{
	ptr = p2pmsg_cmd_encode(ptr, &msg->cmd);
	ptr = iter_encode64u(ptr, msg->uid);
	ptr = iter_encode64u(ptr, msg->packid);
	ptr = iter_encode8u(ptr, msg->attr);
	ptr = iter_encode16u(ptr, msg->len);
	ptr = iter_encode_bytes(ptr, msg->data, msg->len);
	return ptr;
}

const char* p2pmsg_pack_decode(const char *ptr, p2pmsg_pack_t *msg)
{
	ptr = p2pmsg_cmd_decode(ptr, &msg->cmd);
	ptr = iter_decode64u(ptr, &msg->uid);
	ptr = iter_decode64u(ptr, &msg->packid);
	ptr = iter_decode8u(ptr, &msg->attr);
	ptr = iter_decode16u(ptr, &msg->len);
	ptr = iter_decode_bytes(ptr, &msg->data, msg->len);
	return ptr;
}

char* p2pmsg_req_hello_encode(char *ptr, p2pmsg_req_hello_t *msg)
{
	ptr = p2pmsg_cmd_encode(ptr, &msg->cmd);
	ptr = p2pmsg_peer_encode(ptr, &msg->peer);
	ptr = iter_encode64u(ptr, msg->dstuid);
	return ptr;
}

const char* p2pmsg_req_hello_decode(const char *ptr, p2pmsg_req_hello_t *msg)
{
	ptr = p2pmsg_cmd_decode(ptr, &msg->cmd);
	ptr = p2pmsg_peer_decode(ptr, &msg->peer);
	ptr = iter_decode64u(ptr, &msg->dstuid);
	return ptr;
}

char* p2pmsg_ack_hello_encode(char *ptr, p2pmsg_ack_hello_t *msg)
{
	ptr = p2pmsg_cmd_encode(ptr, &msg->cmd);
	ptr = p2pmsg_peer_encode(ptr, &msg->peer);
	return ptr;
}

const char* p2pmsg_ack_hello_decode(const char *ptr, p2pmsg_ack_hello_t *msg)
{
	ptr = p2pmsg_cmd_decode(ptr, &msg->cmd);
	ptr = p2pmsg_peer_decode(ptr, &msg->peer);
	return ptr;
}

char* p2pmsg_req_login_encode(char *ptr, p2pmsg_req_login_t *msg)
{
	ptr = p2pmsg_cmd_encode(ptr, &msg->cmd);
	ptr = p2pmsg_peer_encode(ptr, &msg->peer);
	ptr = iter_encode64u(ptr, msg->upperuid);
	ptr = iter_encode32u(ptr, msg->upperrate);
	ptr = iter_encode64u(ptr, msg->startpackid);
	ptr = iter_encode64u(ptr, msg->maxpackid);
	ptr = iter_encode8u(ptr, msg->push);
	ptr = iter_encode8u(ptr, msg->getpeernum);
	return ptr;
}

const char* p2pmsg_req_login_decode(const char *ptr, p2pmsg_req_login_t *msg)
{
	ptr = p2pmsg_cmd_decode(ptr, &msg->cmd);
	ptr = p2pmsg_peer_decode(ptr, &msg->peer);
	ptr = iter_decode64u(ptr, &msg->upperuid);
	ptr = iter_decode32u(ptr, &msg->upperrate);
	ptr = iter_decode64u(ptr, &msg->startpackid);
	ptr = iter_decode64u(ptr, &msg->maxpackid);
	ptr = iter_decode8u(ptr, &msg->push);
	ptr = iter_decode8u(ptr, &msg->getpeernum);
	return ptr;
}

char* p2pmsg_ack_login_encode(char *ptr, p2pmsg_ack_login_t *msg)
{
	int i;

	ptr = p2pmsg_cmd_encode(ptr, &msg->cmd);
	ptr = iter_encode64u(ptr, msg->uid);
	ptr = iter_encode32u(ptr, msg->logintime);
	ptr = iter_encode32u(ptr, msg->curtime);
	ptr = iter_encode32u(ptr, msg->wanip);
	ptr = iter_encode16u(ptr, msg->wanport);
	ptr = p2pmsg_param_encode(ptr, &msg->param);
	ptr = iter_encode8u(ptr, msg->peernum);
	for (i = 0; i < msg->peernum; i++) {
		ptr = p2pmsg_peer_encode(ptr, &msg->peers[i]);
	}
	return ptr;
}

const char* p2pmsg_ack_login_decode(const char *ptr, p2pmsg_ack_login_t *msg)
{
	int i;

	ptr = p2pmsg_cmd_decode(ptr, &msg->cmd);
	ptr = iter_decode64u(ptr, &msg->uid);
	ptr = iter_decode32u(ptr, &msg->logintime);
	ptr = iter_decode32u(ptr, &msg->curtime);
	ptr = iter_decode32u(ptr, &msg->wanip);
	ptr = iter_decode16u(ptr, &msg->wanport);
	ptr = p2pmsg_param_decode(ptr, &msg->param);
	ptr = iter_decode8u(ptr, &msg->peernum);
	if (msg->peernum > MAX_GETPEERNUM)
		msg->peernum = MAX_GETPEERNUM;
	for (i = 0; i < msg->peernum; i++) {
		ptr = p2pmsg_peer_decode(ptr, &msg->peers[i]);
	}
	return ptr;
}

