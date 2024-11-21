#ifndef __P2P_MGMT__H
#define __P2P_MGMT__H

#include "btype.h"
#include "uthash.h"
#include "cJSON.h"
#include "p2psched.h"
#include "p2phttpsrv.h"
#include "p2ptrksrv.h"

#define MAX_SERVER_UID  1000000

typedef struct p2pmgmt_s p2pmgmt_t;

struct p2pmgmt_s
{
	int            refcnt;
	uint64_t       uid;
	char           ip[16];
	int            port;
	p2pmsg_param_t param;
	char           trkip[16];
	uint16_t       trkport;
	int32_t        trktimediff;
	uint32_t       updatetime;
	uint32_t       lanip;
	rudpworker_pool_t *wp;
	p2phttpsrv_t  *httpsrv;
	p2psched_t    *htsched;
	pthread_mutex_t ht_lck;
	char           cfgfile[1];
};

cJSON *p2pmgmt_loadcfg(const char *cfgfile);
int p2pmgmt_savecfg(const char *cfgfile, cJSON *p2pcfg);
int p2pmgmt_setuid(p2pmgmt_t *mgmt, uint64_t uid);

void p2pmgmt_cfgparam(p2pmsg_param_t *param, cJSON *p2pcfg);
int p2pmgmt_ref(p2pmgmt_t *mgmt);
int p2pmgmt_unref(p2pmgmt_t *mgmt);
p2pmgmt_t *p2pmgmt_new(const char *cfgfile);
p2psched_t *p2pmgmt_getsched(p2pmgmt_t *mgmt, uint32_t chid, const char *puship, uint16_t pushport);
int p2pmgmt_delsched(p2pmgmt_t *mgmt, uint32_t chid);
void p2pmgmt_destroy(p2pmgmt_t *mgmt);

int p2pmgmt_setlanip(p2pmgmt_t *mgmt);

int p2pmgmt_authcreate(uint32_t cid, char *auth, int size, uint32_t curtime);
uint32_t p2pmgmt_authverify(uint32_t cid, char *auth, int len);

#endif
