#include "p2papp.h"
#include "rudpsock.h"
#include "rudpsess.h"

#define TEST_RUDP        0
#if TEST_RUDP
#define P2P_MTU          MAX_MTU
#define P2P_PACK         MAX_PACK
#define P2P_INTERVAL     15
#define P2P_MINRTO       15
#define P2P_FASTRESEND   0
#define P2P_WNDSIZE      1024
#define P2P_XMITMAX      120
#define P2P_SNDTIMEOUT   900

#define PACK_NUM         1024 * 100
#define SEND_NUM         1
#define CLIENT_NUM       1
//#define SERVER_IP        "127.0.0.1"
//#define SERVER_IP        "192.168.1.82"
//#define SERVER_IP        "192.168.100.170"
//#define SERVER_IP        "153.35.82.246"
//#define SERVER_IP        "192.168.210.70"
#define SERVER_IP        "168.168.168.2"
#define SEND_INTERVAL    100

typedef struct peernode_s {
	struct event timer;
	char tag[8];
	uint64_t sumrtt;
	int count;
	int maxrtt;
	uint32_t ts1;
	uint32_t next;
	uint32_t index;
	uint32_t ts2;
	pthread_mutex_t lock;
	rudpsocket_t *rudp;
} peernode_t;

static uint64_t sendnum = 0;

static void test_print_pack(rudpsession_t *session, char *buffer, int len, void *data)
{
	peernode_t *node = (peernode_t *)data;
	uint32_t current;
	uint32_t sn;
	uint32_t ts;
	uint32_t rtt;
	int n = 0, done = 0;

	if (node->ts1 == 0)
		node->ts1 = getcurtime_ms();

	while (n + P2P_PACK <= len) {
		current = getcurtime_ms();
		sn = *(uint32_t*)(buffer + n + 0);
		ts = *(uint32_t*)(buffer + n + 4);
		rtt = current - ts;
		if (sn % 1024 == 0)
		  log_debug("[RECV] %s sn=%d rtt=%d sr=%d rr=%d %llu[%x] %p:%d %d:%d:%d mtu:%d/%d", 
			node->tag, (int)sn, (int)rtt, rudpsess_sendrate(session),
			rudpsess_recvrate(session), sendnum, session->mysessid, session, 
			session->kcp->rx_rto, session->kcp->nsnd_que,
			session->kcp->rcv_total, session->kcp->rcv_succ,
			session->kcp->mtu, session->kcp->maxmtu);
		//if (sn == 0) Sleep(100);
		if (sn != node->next) { // 如果收到的包不连续
			//log_debug("ERROR %s sn %d<->%d %p", node->tag, (int)sn, (int)node->next, session);
			//break;
		}

		n += P2P_PACK;
		pthread_mutex_lock(&node->lock);
		node->next++;
		node->sumrtt += rtt;
		node->count++;
		if (rtt > (uint32_t)node->maxrtt)
			node->maxrtt = rtt;
		if (node->next == SEND_NUM * PACK_NUM)
			done = 1;
		pthread_mutex_unlock(&node->lock);
	}

	if (done) {
		log_debug("%s result: %dms avgrtt=%lld maxrtt=%d next=%d [%x] %p:%d\n",
			node->tag, getcurtime_ms() - node->ts1, 
			node->count ? node->sumrtt / node->count : -1, 
			node->maxrtt, node->next, session->mysessid, session, session->kcp->rx_rto);
		//rudpsess_close(session, 0);
		//rudpsock_close(session->rudpsock);
	}
}

int test_notifycb(rudpsession_t *session, char *buffer, int len, int ntftype, void *data)
{
	if (ntftype == RUDP_NOTIFY_FAIL)
		log_debug("send fail! [%x] %p\n", session->mysessid, session);
	return 0;
}

int test_closecb(rudpsession_t *session, void *data)
{
	peernode_t *node = (peernode_t *)data;

	//if (node->next <= 0)
	//	return 0;
	log_debug("session closed! next=%d [%x]\n", node->next, session->mysessid);
	log_debug("%s result: %dms avgrtt=%lld maxrtt=%d sr=%d rr=%d [%x] %p\n",
		node->tag, getcurtime_ms() - node->ts1,
		node->count ? node->sumrtt / node->count : -1, 
		node->maxrtt, rudpsess_sendrate(session), 
		rudpsess_recvrate(session), session->mysessid, session);
	node->index = -1;
	event_del(&node->timer);
	return 0;
}

int test_destroycb(rudpsocket_t *rudpsock)
{
	return 0;
}

void test_server_cb(rudpsession_t *session, char *buffer, int len, void *data)
{
	//rudpsess_send(session, buffer, len, getcurtime_ms());
	test_print_pack(session, buffer, len, data);
	rudpbuffer_free(buffer);
}

void test_client_cb(rudpsession_t *session, char *buffer, int len, void *data)
{
	test_print_pack(session, buffer, len, data);
	rudpbuffer_free(buffer);
}

void test_client(void *arg)
{
	rudpsession_t *session = (rudpsession_t *)arg;
	rudpsocket_t *rudp = session->rudpsock;
	peernode_t *node = (peernode_t *)rudp->data;
	uint32_t current;
	int i;
	char buffer[P2P_PACK];

	for (i = 0; i < PACK_NUM; i++) {
		current = getcurtime_ms();
		//log_debug("[SEND] %s sn=%d ts=%d rtt=%d [%x] %p\n",
		//	node->tag, node->index, current, current - node->ts2, session->mysessid, session);
		node->ts2 = current;
		((uint32_t*)buffer)[0] = node->index++;
		((uint32_t*)buffer)[1] = current;
		rudpsess_send(session, buffer, P2P_PACK, current);
		sendnum++;
	}
	/*if (node->index >= 0 && node->index < SEND_NUM * PACK_NUM) {
		//event_add(&node->timer, rudptv_set(tv, SEND_INTERVAL));
		rudpsess_ref(session);
		//rudpworker_addjob(rudp->wp, test_client, session, 0);
		test_client(session);
	}*/
	rudpsess_unref(session);
}

void test_timer(evutil_socket_t fd, short event, void *arg)
{
	rudpsession_t *session = (rudpsession_t *)arg;
	rudpsocket_t *rudp = session->rudpsock;
	peernode_t *node = (peernode_t *)rudp->data;
	struct timeval tv = { 0, 15000 };

	if (session->kcp->nsnd_que < 10240) {
		rudpsess_ref(session);
		//rudpworker_addjob(rudp->wp, test_client, session, 0);
		test_client(session);
	}
	log_debug("[SEND] %s sn=%d sr=%d rr=%d %llu[%x] %p nque:%d rto:%d:%d:%d snd:%d:%d:%d:%d:%d cwnd:%d:%d:%d:%d mtu:%d/%d",
		node->tag, (int)node->index, rudpsess_sendrate(session),
		rudpsess_recvrate(session), sendnum, session->mysessid, session,
		session->kcp->nsnd_que, session->kcp->rx_rto, session->kcp->rx_srtt, session->kcp->rx_rttval,
		session->kcp->snd_total, session->kcp->snd_first, session->kcp->snd_succ, session->kcp->snd_una, session->kcp->snd_nxt,
		session->kcp->cwnd, session->kcp->nsnd_buf, session->kcp->nsnd_que, session->kcp->ssthresh, session->kcp->mtu, session->kcp->maxmtu);
	event_add(&node->timer, &tv);
}

void test_srvtimer(evutil_socket_t fd, short event, void *arg)
{
	peernode_t *nodesrv = (peernode_t *)arg;
	struct timeval tv = { 0, 5000 };
	uint32_t ts = getcurtime_ms();

	event_add(&nodesrv->timer, &tv);
	printf("curtime:%u %d\n", ts, ts - nodesrv->ts1);
	nodesrv->ts1 = ts;
}

uint32_t gettimems()
{
#ifdef _WIN32
#if 0
	return GetTickCount();
#else
	static long addsec = 0;
	static int64_t freq = 1;
	int64_t qpc;
	if (addsec == 0) {
		QueryPerformanceFrequency((LARGE_INTEGER *)&freq);
		freq = (freq == 0) ? 1 : freq;
		QueryPerformanceCounter((LARGE_INTEGER *)&qpc);
		addsec = (long)time(NULL);
		addsec = addsec - (long)((qpc / freq) & 0x7fffffff);
	}
	QueryPerformanceCounter((LARGE_INTEGER *)&qpc);
	return (uint32_t)((qpc / freq + (uint64_t)addsec) * 1000 + (qpc % freq) * 1000 / freq);
#endif
#else
	return getcurtime_ms();
#endif
}

#ifdef _WIN32
int usleep(long usec)
{
	struct timeval tv;
	fd_set dummy;
	SOCKET s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	FD_ZERO(&dummy);
	FD_SET(s, &dummy);
	tv.tv_sec = usec / 1000000L;
	tv.tv_usec = usec % 1000000L;
	return select(0, 0, 0, &dummy, &tv);
}

typedef NTSTATUS(CALLBACK *NTSETTIMERRESOLUTION)(IN ULONG DesiredTime, IN BOOLEAN SetResolution, OUT PULONG ActualTime);
typedef NTSTATUS(CALLBACK *NTQUERYTIMERRESOLUTION)(OUT PULONG MaximumTime, OUT PULONG MinimumTime, OUT PULONG CurrentTime);
#endif

void testTimerResolution()
{
#ifdef _WIN32
	HMODULE h = LoadLibrary(_T("ntdll.dll"));
	NTSETTIMERRESOLUTION NtSetTimerResolution = (NTSETTIMERRESOLUTION)GetProcAddress(h, "NtSetTimerResolution");
	NTQUERYTIMERRESOLUTION NtQueryTimerResolution = (NTQUERYTIMERRESOLUTION)GetProcAddress(h, "NtQueryTimerResolution");
	FreeLibrary(h);

	ULONG ulMinRes = 0;
	ULONG ulMaxRes = 0;
	ULONG ulCurRes = 0;
	NtQueryTimerResolution(&ulMinRes, &ulMaxRes, &ulCurRes);
	printf("MMR:  %d   %d   %d\n", ulMinRes, ulMaxRes, ulCurRes);

	ULONG actualResolution = 0;
	NTSTATUS r = NtSetTimerResolution(10000, TRUE, &actualResolution);
	NtQueryTimerResolution(&ulMinRes, &ulMaxRes, &ulCurRes);
	printf("MMR:  %d   %d   %d %u\n", ulMinRes, ulMaxRes, ulCurRes, r);

	uint32_t t1 = getcurtime_ms(), t2, i;
	for (i = 0; i < 100; i++) {
		usleep(3000);
		t2 = getcurtime_ms();
		printf("curtime:%u %d\n", t2, t2 - t1);
		t1 = t2;
	}
#endif
}
#endif

static void signal_cb(evutil_socket_t sig, short events, void *user_data)
{
	struct event_base *evbase = user_data;
	struct timeval delay = { 2, 0 };

	printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");
	event_base_loopexit(evbase, &delay);
}

int main(int argc, char *argv[])
{
	struct event_base *evbase = NULL;
	struct event_config *evcfg;
	struct event *signal_event;
	p2pmgmt_t *mgmt = NULL;
	p2ptrksrv_t *tracker = NULL;
#if TEST_RUDP
	const char *trackerip = "127.0.0.1";
	short trackerport = 19999, i;
	rudpworker_pool_t *wp;
	rudpsocket_t *rudpsrv = NULL, *rudpcli;
	rudpsession_t *sesscli;
	peernode_t nodesrv = { 0 }, nodecli[100] = { 0 };
	struct timeval tv = { 1, 5000 };
#endif

	app_log_init(NULL, NULL);
	mstat_init(0);
	rudpsock_init();

	log_info("version %s %s", __DATE__, __TIME__);

	evcfg = event_config_new();
	if (evcfg) {
		event_config_set_flag(evcfg, EVENT_BASE_FLAG_PRECISE_TIMER);
		evbase = event_base_new_with_config(evcfg);
		event_config_free(evcfg);
	}

#if TEST_RUDP
	wp = rudpworker_new(4, NULL);
	if (argc > 1)
		trackerip = argv[1];
#endif

	signal_event = evsignal_new(evbase, SIGINT, signal_cb, (void *)evbase);
	event_add(signal_event, NULL);

#if TEST_RUDP
	strxcpy(nodesrv.tag, sizeof(nodesrv.tag), "srv", 3);
	nodesrv.ts1 = gettimems();
	nodesrv.ts2 = getcurtime_ms();
	pthread_mutex_init(&nodesrv.lock, 0);
	nodesrv.rudp = rudpsrv = rudpsock_new(wp, "0.0.0.0", trackerport, 0, RUDPSESS_TIMEOUT,
		RUDP_MAXMTU, P2P_INTERVAL, P2P_MINRTO, P2P_FASTRESEND, P2P_WNDSIZE, P2P_XMITMAX, P2P_SNDTIMEOUT,
		RUDP_NOTIFY_FAIL, test_server_cb, test_notifycb, test_closecb, test_destroycb, &nodesrv);
	//event_assign(&nodesrv.timer, evbase, -1, 0, test_srvtimer, &nodesrv);
	//event_add(&nodesrv.timer, rudptv_set(tv, 1500));

#ifdef SERVER_IP
	trackerip = SERVER_IP;
	for (i = 0; i < CLIENT_NUM; i++) {
		snprintf(nodecli[i].tag, sizeof(nodecli[i].tag), "cli%02d", i);
		nodecli[i].ts2 = getcurtime_ms();
		pthread_mutex_init(&nodecli[i].lock, 0);
		nodecli[i].rudp = rudpcli = rudpsock_new(wp, "0.0.0.0", 0, 0, RUDPSESS_TIMEOUT,
			RUDP_MAXMTU, P2P_INTERVAL, P2P_MINRTO, P2P_FASTRESEND, P2P_WNDSIZE, P2P_XMITMAX, P2P_SNDTIMEOUT,
			RUDP_NOTIFY_FAIL, test_client_cb, test_notifycb, test_closecb, test_destroycb, &nodecli[i]);
		sesscli = rudpsock_connect(rudpcli, inet_addr(trackerip), trackerport);
		event_assign(&nodecli[i].timer, evbase, -1, 0, test_timer, sesscli);
		event_add(&nodecli[i].timer, rudptv_set(tv, SEND_INTERVAL));
		rudpsess_unref(sesscli);
	}
#endif

#else
	const char *cfgfile = "livecfg.json";
	if (argc > 1) cfgfile = argv[1];

	mgmt = p2pmgmt_new(cfgfile);
	tracker = p2ptrksrv_new(cfgfile);
#endif

	event_base_dispatch(evbase);
	event_free(signal_event);
	event_base_free(evbase);
	
#if TEST_RUDP
	rudpsock_close(rudpsrv);
	for (i = 0; i < CLIENT_NUM; i++)
		rudpsock_close(nodecli[i].rudp);
	rudpworker_destroy(wp);
#endif

	if (mgmt != NULL) p2pmgmt_destroy(mgmt);
	if (tracker != NULL) p2ptrksrv_destroy(tracker);

	rudpsock_cleanup();
	mstat_cleanup();
	app_log_destroy(NULL);
	return 0;
}
