#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	"ts.h"
#include	"pat.h"
#include	"ts_psi_mgr.h"

// declaration
static int fn_init(void *self);
static int fn_set_pat_pmt(void *self, uint8_t *buff, int nlen);
static int fn_is_ready(void *self);
static uint8_t * fn_get_pat(void *self);
static uint8_t * fn_get_pmt(void *self);
static int fn_get_stream_type(void *self, uint16_t pid, char *szInfo, uint16_t len);
static int fn_is_video(void *self, uint16_t pid);
static uint16_t fn_get_video_encoder(void *self);
// end

// implementation
TS_PSI_MGR * ts_psi_get_manage()
{
	TS_PSI_MGR * hdl = (TS_PSI_MGR *)malloc(sizeof(TS_PSI_MGR));

	hdl->fn_init = fn_init;
	hdl->fn_set_pat_pmt = fn_set_pat_pmt;
	hdl->fn_is_ready = fn_is_ready;
	hdl->fn_get_pat = fn_get_pat;
	hdl->fn_get_pmt = fn_get_pmt;
	hdl->fn_get_stream_type = fn_get_stream_type;
	hdl->fn_is_video = fn_is_video;
	hdl->fn_get_video_encoder = fn_get_video_encoder;

	hdl->pat = NULL;
	hdl->pmt = NULL;

	return hdl;
}

void ts_psi_release_manage(TS_PSI_MGR *hdl)
{
	ts_psi_pat_close_handle(hdl->pat);
	ts_psi_pmt_close_handle(hdl->pmt);

	free(hdl);
}

static int fn_init(void *self)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;

	ppsi->pat = ts_psi_pat_get_handle();
	ppsi->pat->fn_init(ppsi->pat);

	ppsi->pmt = ts_psi_pmt_get_handle();
	ppsi->pmt->fn_init(ppsi->pmt);

	return 0;
}

static int fn_set_pat_pmt(void *self, uint8_t *buff, int nlen)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;
	TS_PSI_PAT *pat = ppsi->pat;
	TS_PSI_PMT *pmt = ppsi->pmt;

	if (nlen != TS_SIZE) return -1;
	if (ppsi->pat == NULL || ppsi->pmt == NULL) return -1;

	// 1. find pat
	if (pat->fn_set_cont(pat, buff, nlen) >= 0)
	{
		pmt->fn_set_pmt_id(pmt, pat->fn_get_pmt_id(pat, 0));
		return 0;
	}

	// 2. find pmt
	if (ts_get_pid(buff) == pat->fn_get_pmt_id(pat, 0))
	{
		if (pmt->fn_set_cont(pmt, buff, nlen) == 0)
		{
			ppsi->stream_index[TS_VIDEO_POS] = pmt->fn_get_stream_id(pmt, TS_MEDIA_TYPE_VIDEO);
		}
	}

	return 0;
}

static int fn_is_ready(void *self)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;
	TS_PSI_PAT *pat = ppsi->pat;
	TS_PSI_PMT *pmt = ppsi->pmt;

	if (ppsi->pat == NULL || ppsi->pmt == NULL) return 0;
	if (pat->fn_get_cont(pat) != NULL &&
		pmt->fn_get_cont(pmt) != NULL)
	{
		return 1;
	}
	return 0;
}

static uint8_t * fn_get_pat(void *self)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;
	return ppsi->pat->fn_get_cont(ppsi->pat);
}

static uint8_t * fn_get_pmt(void *self)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;
	return ppsi->pmt->fn_get_cont(ppsi->pmt);
}

static int fn_get_stream_type(void *self, uint16_t pid, char *szInfo, uint16_t len)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;
	TS_PSI_PAT *pat = ppsi->pat;
	TS_PSI_PMT *pmt = ppsi->pmt;

	int nret = -1;

	if (ppsi->pat == NULL || ppsi->pmt == NULL) return 0;
	if (pid == PAT_PID)
	{
		nret = TS_MEDIA_TYPE_PAT;
		snprintf(szInfo, len, "PAT");
	}
	else if (pid == pat->fn_get_pmt_id(pat, 0))
	{
		nret = TS_MEDIA_TYPE_PMT;
		snprintf(szInfo, len, "PMT");
	}
	else
	{
		nret = pmt->fn_get_stream_type(pmt, pid, szInfo, len);
	}

	return nret;
}

static int fn_is_video(void *self, uint16_t pid)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;
	if (pid == ppsi->stream_index[TS_VIDEO_POS].pid)
		return 1;
	return 0;
}

static uint16_t fn_get_video_encoder(void *self)
{
	TS_PSI_MGR *ppsi = (TS_PSI_MGR *)self;
	return ppsi->stream_index[TS_VIDEO_POS].enc_type;
}

