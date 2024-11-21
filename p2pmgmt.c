#include "p2pmgmt.h"
#include "app_log.h"
#include "aes.h"

#define P2P_MAXIDLE      RUDPSESS_TIMEOUT
#define P2P_MTU          MAX_MTU
#define P2P_INTERVAL     30
#define P2P_MINRTO       30
#define P2P_FASTRESEND   0
#define P2P_WNDSIZE      1024
#define P2P_XMITMAX      25
#define P2P_SNDTIMEOUT   120
#define P2P_PACK         1316
#define P2P_BLOCK        512
#define P2P_CACHE        32
#define P2P_SKIP         1024
#define P2P_TRKINTER     10000
#define P2P_BLKTIMEOUT   3000
#define P2P_HLOTIMEOUT   5000
#define P2P_MAXLOWERS    0
#define P2P_MAXLOWERC    5

int p2pmgmt_ref(p2pmgmt_t *mgmt)
{
	return _sync_add32(&mgmt->refcnt, 1);
}

int p2pmgmt_unref(p2pmgmt_t *mgmt)
{
	int refcnt = _sync_add32(&mgmt->refcnt, -1);
	if (refcnt == 1) {
		log_debug("p2pmgmt freed: %p", mgmt);
		pthread_mutex_destroy(&mgmt->ht_lck);
		if (mgmt->wp->owner == mgmt) rudpworker_destroy(mgmt->wp);
		kfree(mgmt);
	}
	return refcnt;
}

void p2pmgmt_cfgparam(p2pmsg_param_t *param, cJSON *p2pcfg)
{
	cJSON *ci, *ci2;

	param->len = sizeof(p2pmsg_param_t);
	param->mtu = P2P_MTU;
	param->interval = P2P_INTERVAL;
	param->minrto = P2P_MINRTO;
	param->fastresend = P2P_FASTRESEND;
	param->xmitmax = P2P_XMITMAX;
	param->sndtimeout = P2P_SNDTIMEOUT;
	param->wndsize = P2P_WNDSIZE;
	param->maxidle = P2P_MAXIDLE;
	param->packsize = P2P_PACK;
	param->blocksize = P2P_BLOCK;
	param->blocknum = P2P_CACHE;
	param->packskip = P2P_SKIP;
	param->trkinter = P2P_TRKINTER;
	param->blktimeout = P2P_BLKTIMEOUT;
	param->hlotimeout = P2P_HLOTIMEOUT;
	param->maxlowers = P2P_MAXLOWERS;
	param->maxlowerc = P2P_MAXLOWERC;

	if (!(ci = cJSON_GetObjectItem(p2pcfg, "param"))) return;
	if (ci2 = cJSON_GetObjectItem(ci, "mtu"))
		param->mtu = ci2->valueint < 588 ? 588 : 
			(ci2->valueint > MAX_MTU ? MAX_MTU : ci2->valueint);
	if (ci2 = cJSON_GetObjectItem(ci, "interval"))
		param->interval = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "minrto"))
		param->minrto = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "fastresend"))
		param->fastresend = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "xmitmax"))
		param->xmitmax = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "sndtimeout"))
		param->sndtimeout = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "wndsize"))
		param->wndsize = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "maxidle"))
		param->maxidle = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "packsize"))
		param->packsize = (ci2->valueint < 564) ? 564 : 
			(ci2->valueint > (param->mtu - RUDP_OVERHEAD) ?
				(param->mtu - RUDP_OVERHEAD) : ci2->valueint);
	if (ci2 = cJSON_GetObjectItem(ci, "blocksize"))
		param->blocksize = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "blocknum"))
		param->blocknum = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "packskip"))
		param->packskip = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "trkinter"))
		param->trkinter = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "blktimeout"))
		param->blktimeout = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "hlotimeout"))
		param->hlotimeout = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "maxlowers"))
		param->maxlowers = ci2->valueint;
	if (ci2 = cJSON_GetObjectItem(ci, "maxlowerc"))
		param->maxlowerc = ci2->valueint;
}

cJSON *p2pmgmt_loadcfg(const char *cfgfile)
{
	FILE *fp = fopen(cfgfile, "r");
	char buf[8192];
	int len;

	if (!fp) {
		log_error("read config fail: %s", cfgfile);
		return NULL;
	}
	len = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	buf[len] = '\0';
	return cJSON_Parse(buf);
}

int p2pmgmt_savecfg(const char *cfgfile, cJSON *p2pcfg)
{
	FILE *fp;
	char *cfg;

	fp = fopen(cfgfile, "w");
	if (!fp)
		return -1;
	cfg = cJSON_Print(p2pcfg);
	fwrite(cfg, 1, strlen(cfg), fp);
	fclose(fp);
	cJSON_free(cfg);
	return 0;
}

int p2pmgmt_setuid(p2pmgmt_t *mgmt, uint64_t uid)
{
	FILE *fp;
	char buf[8192];
	int len;
	cJSON *p2pcfg, *ci;

	if (mgmt->uid == uid)
		return 0;
	mgmt->uid = uid;

	fp = fopen(mgmt->cfgfile, "r+");
	if (!fp) {
		log_error("read config fail: %s", mgmt->cfgfile);
		return -1;
	}
	len = fread(buf, 1, sizeof(buf) - 1, fp);
	buf[len] = '\0';

	p2pcfg = cJSON_Parse(buf);
	if (!p2pcfg) {
		log_error("load config fail: %s", mgmt->cfgfile);
		fclose(fp);
		return -1;
	}
	
	ci = cJSON_GetObjectItem(p2pcfg, "uid");
	if (!ci || strtoull(ci->valuestring, NULL, 10) != uid) {
		snprintf(buf, sizeof(buf), "%llu", uid);
		if (ci)
			cJSON_SetValuestring(ci, buf);
		else
			cJSON_AddStringToObject(p2pcfg, "uid", buf);
		memset(buf, ' ', len);
		cJSON_PrintPreallocated(p2pcfg, buf, sizeof(buf), 1);
		fseek(fp, 0, SEEK_SET);
		fwrite(buf, 1, strlen(buf), fp);
	}
	
	cJSON_Delete(p2pcfg);
	fclose(fp);
	return 0;
}

p2pmgmt_t *p2pmgmt_new(const char *cfgfile)
{
	cJSON *p2pcfg, *ci, *ci2, *ci3;
	int threadnum = 4, n, i;
	p2pmgmt_t *mgmt;
	
	p2pcfg = p2pmgmt_loadcfg(cfgfile);
	if (!p2pcfg) {
		log_error("load config fail: %s", cfgfile);
		return NULL;
	}

	if (ci = cJSON_GetObjectItem(p2pcfg, "loglevel")) {
		app_log_setlevel(ci->valueint);
	}

	n = strlen(cfgfile);
	mgmt = kcalloc(1, sizeof(p2pmgmt_t) + n);
	pthread_mutex_init(&mgmt->ht_lck, 0);
	mgmt->refcnt = 1;
	memcpy(mgmt->cfgfile, cfgfile, n);
	mgmt->trktimediff = 0;
	p2pmgmt_cfgparam(&mgmt->param, p2pcfg);
	mgmt->updatetime = 0;

	if (ci = cJSON_GetObjectItem(p2pcfg, "uid")) {
		mgmt->uid = strtoull(ci->valuestring, NULL, 10);
		if (mgmt->uid > 0 && mgmt->uid <= MAX_SERVER_UID)
			mgmt->port = 10000;
	}
	if (ci = cJSON_GetObjectItem(p2pcfg, "ip")) {
		strxcpy(mgmt->ip, sizeof(mgmt->ip), ci->valuestring, -1);
	}
	if (ci = cJSON_GetObjectItem(p2pcfg, "port")) {
		mgmt->port = ci->valueint;
	}
	p2pmgmt_setlanip(mgmt);

	if (ci = cJSON_GetObjectItem(p2pcfg, "threadnum")) {
		threadnum = ci->valueint;
	}
	mgmt->wp = rudpworker_new(threadnum, mgmt);

	if (ci = cJSON_GetObjectItem(p2pcfg, "tracker")) {
		if (ci2 = cJSON_GetObjectItem(ci, "ip"))
			strxcpy(mgmt->trkip, sizeof(mgmt->trkip), ci2->valuestring, -1);
		if (ci2 = cJSON_GetObjectItem(ci, "port"))
			mgmt->trkport = ci2->valueint;
	}

	if (ci = cJSON_GetObjectItem(p2pcfg, "pushsrv")) {
		cJSON_ArrayForEach(ci2, ci) {
			uint32_t cid = 0;
			const char *ip = "127.0.0.1";
			uint16_t port;
			p2psched_t *sched;

			n = 0;
			if (ci3 = cJSON_GetObjectItem(ci2, "num"))
				n = ci3->valueint;
			if (ci3 = cJSON_GetObjectItem(ci2, "cid"))
				cid = ci3->valueint;
			if (ci3 = cJSON_GetObjectItem(ci2, "ip"))
				ip = ci3->valuestring;
			if (ci3 = cJSON_GetObjectItem(ci2, "port")) {
				if ((port = ci3->valueint) > 0) {
					if (n <= 0)
						n = 1;
					for (i = 0; i < n; i++) {
						sched = p2pmgmt_getsched(mgmt, cid + i, ip, port + i);
						if (sched) p2psched_unref(sched);
					}
				}
			}
		}
	}

	if (ci = cJSON_GetObjectItem(p2pcfg, "httpsrv")) {
		p2phttpsrv_t *httpsrv;
		char ip[16] = "0.0.0.0";
		uint16_t port = 0;
		struct timeval tv = { 0, 10 * 1000 };

		if (ci2 = cJSON_GetObjectItem(ci, "ip"))
			strxcpy(ip, sizeof(ip), ci2->valuestring, -1);
		if (ci2 = cJSON_GetObjectItem(ci, "port")) {
			if ((port = ci2->valueint) > 0) {
				mgmt->httpsrv = httpsrv = p2phttpsrv_new(mgmt, ip, port);
			}
		}
	}

	cJSON_Delete(p2pcfg);
	return mgmt;
}

p2psched_t *p2pmgmt_getsched(p2pmgmt_t *mgmt, uint32_t cid, const char *puship, uint16_t pushport)
{
	p2psched_t *sched = NULL;

	pthread_mutex_lock(&mgmt->ht_lck);
	HASH_FIND(hhsched, mgmt->htsched, &cid, sizeof(cid), sched);
	if (sched == NULL) {
		sched = p2psched_new(mgmt, cid, puship, pushport);
		if (sched != NULL)
			HASH_ADD(hhsched, mgmt->htsched, cid, sizeof(sched->cid), sched);
	}
	if (sched) p2psched_ref(sched);
	pthread_mutex_unlock(&mgmt->ht_lck);
	return sched;
}

int p2pmgmt_delsched(p2pmgmt_t *mgmt, uint32_t cid)
{
	p2psched_t *sched = NULL;

	pthread_mutex_lock(&mgmt->ht_lck);
	HASH_FIND(hhsched, mgmt->htsched, &cid, sizeof(cid), sched);
	if (sched != NULL) {
		if (sched->tcpsrv != NULL) {
			p2psched_unref(sched);
			pthread_mutex_unlock(&mgmt->ht_lck);
			log_debug("p2psched:%p %u inuse, not closed", sched, sched->cid);
			return 0;
		}
		HASH_DELETE(hhsched, mgmt->htsched, sched);
		p2psched_unref(sched);
	}
	pthread_mutex_unlock(&mgmt->ht_lck);
	
	if (sched != NULL) {
		log_debug("p2psched:%p %u is now closing", sched, sched->cid);
		p2psched_destroy(sched);
	}
	return 1;
}

void p2pmgmt_destroy(p2pmgmt_t *mgmt)
{
	p2psched_t *sched, *nextsched;

	p2phttpsrv_destroy(mgmt->httpsrv);
	pthread_mutex_lock(&mgmt->ht_lck);
	HASH_ITER(hhsched, mgmt->htsched, sched, nextsched) {
		p2psched_destroy(sched);
	}
	pthread_mutex_unlock(&mgmt->ht_lck);
	p2pmgmt_unref(mgmt);
}

int p2pmgmt_setlanip(p2pmgmt_t *mgmt)
{
	struct sockaddr_in serv;
	int sockfd, err;
	
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr("8.8.8.8");
	serv.sin_port = htons(53);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == INVALID_SOCKET)
		return -1;

	err = connect(sockfd, (const struct sockaddr*) &serv, sizeof(serv));
	if (err == SOCKET_ERROR) {
		closesocket(sockfd);
		return err;
	}

	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	err = getsockname(sockfd, (struct sockaddr*)&addr, &addrlen);
	if (err == SOCKET_ERROR) {
		closesocket(sockfd);
		return err;
	}

	mgmt->lanip = addr.sin_addr.s_addr;
	closesocket(sockfd);
	return 0;
}

int p2pmgmt_authcreate(uint32_t cid, char *auth, int size, uint32_t curtime)
{
	static unsigned char key[16] = { 0x31, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
	static unsigned char iv[16] = { 0x61, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	struct AES_ctx ctx;
	
	if (size <= 32)
		return 0;
	snprintf(auth, size, "%08x%08x", cid, (curtime - 1696089600) / 3);
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_encrypt_buffer(&ctx, auth, 16);
	return snprintf(auth, size, "%016llx%016llx", *(uint64_t *)auth, *(uint64_t *)(auth + 8));
}

#define hex2val(_v,_s,_i,_b,_e) for (_i = _b, _v = 0; _i < _e; _i++) { \
	_v = (_v << 4) | ((_s[i] >= '0' && _s[i] <= '9') ? (_s[i] - '0') : \
			((_s[i] >= 'a' && _s[i] <= 'f') ? (10 + _s[i] - 'a') : \
			((_s[i] >= 'A' && _s[i] <= 'F') ? (10 + _s[i] - 'A') : 0))); \
}

uint32_t p2pmgmt_authverify(uint32_t cid, char *auth, int len)
{
	static unsigned char key[16] = { 0x31, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
	static unsigned char iv[16] = { 0x61, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	struct AES_ctx ctx;
	uint64_t v64;
	uint32_t v32;
	int i;

	if (len < 32)
		return 0;

	hex2val(v64, auth, i, 0, 16);
	*(uint64_t *)auth = v64;

	hex2val(v64, auth, i, 16, 32);
	*(uint64_t *)(auth + 8) = v64;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, auth, 16);
	
	hex2val(v32, auth, i, 0, 8);
	if (v32 != cid)
		return 0;
	
	hex2val(v32, auth, i, 8, 16);
	return v32 * 3 + 1696089600; //auth time
}
