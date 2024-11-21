#include <stdio.h>
#include <stdlib.h>
#include "pes.h"
#include "pat.h"
#include "ts_stream.h"

// declaration
#define AV_RB16(x) ((((const uint8_t*)(x))[0] << 8) | \
					 ((const uint8_t*)(x))[1])
// public function
static int fn_init(void *self);
static int fn_detect(void *self, uint8_t *buff, int len);
static int fn_is_keyframe(void *self, uint16_t enc_type);
static int64_t fn_get_pts(void *self);
static int fn_set_pat_pmt(void *self, char *raw_buf, int len);
static int fn_set_pack(void *self, void *raw_buf, int len);
// private function
static int sf_is_cavs_iframe(uint8_t *vdata);
static int sf_is_h264_iframe(uint8_t *vdata, int nAdpLen);
static int sf_is_h265_iframe(uint8_t *vdata, int nAdpLen);
static int sf_is_mpeg_iframe(uint8_t *vdata);
// end

// implementation
TS_StreamHandle *ts_stream_get_handle()
{
	TS_StreamHandle *hdl = (TS_StreamHandle *)malloc(sizeof(TS_StreamHandle));
	hdl->fn_init = fn_init;
	hdl->fn_detect = fn_detect;
	hdl->fn_is_keyframe = fn_is_keyframe;
	hdl->fn_get_pts = fn_get_pts;
	hdl->fn_set_pat_pmt = fn_set_pat_pmt;
	hdl->fn_set_pack = fn_set_pack;
	hdl->pPSIHdl = NULL;
	return hdl;
}

void ts_stream_close_handle(TS_StreamHandle *hdl)
{
	if (hdl->pPSIHdl) free(hdl->pPSIHdl);
	if (hdl) free(hdl);
}

static int fn_init(void *self)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)self;
	psh->pBuff = NULL;
	psh->nLength = 0;
	psh->nPTS = 0;
	psh->nPesLen = 0;
	psh->pPayload = NULL;

	psh->pPSIHdl = ts_psi_get_manage();
	psh->pPSIHdl->fn_init(psh->pPSIHdl);
	return 0;
}

static int fn_detect(void *self, uint8_t *buff, int len)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)self;
	uint8_t *pes = NULL;

	if (len != TS_SIZE) 
		return 0;

	psh->pBuff = buff;
	psh->nLength = len;

	// 1. if unit start 
	if (!ts_get_unitstart(buff))
		return 0;

	// 2. if pes video
	pes = ts_payload(buff);
	if (pes >= buff + TS_SIZE)
		return 0;

	if (!pes_validate(pes))
		return 0;

	if (pes_get_streamid(pes) != PES_STREAM_ID_VIDEO_MPEG)
		return 0;

	// 3. get pts
	if (!pes_has_pts(pes))
		return 0;

	if (!pes_validate_pts(pes))
		return 0;

	psh->pPayload = pes_payload(pes);
	psh->nPTS = pes_get_pts(pes);

	if (ts_has_adaptation(buff))
	{
		psh->nPesLen = TS_HEADER_SIZE + 1 + ts_get_adaptation(buff) +
			PES_HEADER_SIZE + PES_HEADER_OPTIONAL_SIZE + pes_get_headerlength(pes);
	}
	else
	{
		psh->nPesLen = TS_HEADER_SIZE + PES_HEADER_SIZE +
			PES_HEADER_OPTIONAL_SIZE + pes_get_headerlength(pes);
	}

	return 1;
}

static int fn_is_keyframe(void *self, uint16_t enc_type)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)self;
	int nret = 0;

	switch (enc_type)
	{
	case TS_STREAM_H264:
		nret = sf_is_h264_iframe(psh->pPayload, psh->nPesLen);
		break;

	case TS_STREAM_H265:
		nret = sf_is_h265_iframe(psh->pPayload, psh->nPesLen);
		break;

	case TS_STREAM_CAVS:
		nret = sf_is_cavs_iframe(psh->pPayload + psh->nPesLen);
		break;

	case TS_STREAM_MPEG2:
		nret = sf_is_mpeg_iframe(psh->pPayload + psh->nPesLen);
		break;

	default:
		nret = 0;
	}

	return nret;
}

static int sf_is_h264_iframe(uint8_t *buf, int nAdpLen)
{
	uint32_t strid = 0;
	int i;

	for (i = 0; i < (TS_SIZE - nAdpLen); i++)
	{
		strid = (strid << 8) | buf[i];
		if ((strid >> 8) == 1)
		{
			// we found a start code - remove the ref_idc from the nal type 
			uint8_t nal_type = strid & 0x1f;
			if (nal_type == 0x05)
				return 1; // h.264 IDR picture start 
		}
	}
	return 0;
}

static int sf_is_h265_iframe(uint8_t *buf, int nAdpLen)
{
	uint32_t strid = 0;
	int i;

	for (i = 0; i < (TS_SIZE - nAdpLen); i++)
	{
		strid = (strid << 8) | buf[i];
		if ((strid >> 8) == 1)
		{
			// we found a start code - remove the ref_idc from the nal type 
			uint8_t nal_type = (strid & 0x7e) >> 1;
			if (nal_type == 0x13)
				return 1; // h.265 IDR picture start 
		}
	}
	return 0;
}

static int sf_is_cavs_iframe(uint8_t *vdata)
{
	if (vdata[0] == 0x00 && vdata[1] == 0x00 &&
		vdata[2] == 0x01 && vdata[3] == 0xb0)
	{
		uint8_t *ptr = vdata + 18;
		if (ptr[0] == 0x00 && ptr[1] == 0x00 &&
			ptr[2] == 0x01 && ptr[3] == 0xb3)
			return 1;
	}
	return 0;
}

static int sf_is_mpeg_iframe(uint8_t *vdata)
{
	if (vdata[0] == 0x00 && vdata[1] == 0x00 &&
		vdata[2] == 0x01 && vdata[3] == 0xb3)
		return 1;
	return 0;
}

static int64_t fn_get_pts(void *self)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)self;
	return psh->nPTS;
}

static int fn_set_pat_pmt(void *self, char *raw_buf, int nlen)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)self;
	TS_PSI_MGR *psm = psh->pPSIHdl;

	psm->fn_set_pat_pmt(psm, (uint8_t *)raw_buf, nlen);
	if (psm->fn_is_ready(psm) && (ts_get_pid((uint8_t *)raw_buf) != PAT_PID))
		return 1;
	return -1;
}

static int fn_set_pack(void *self, void *raw_buf, int nlen)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)self;
	TS_PSI_MGR *psm = psh->pPSIHdl;
	uint16_t nEncoder = TS_STREAM_UNKONWN;

	if (nlen != TS_SIZE) return 0;

	if (psm->fn_is_video(psm, ts_get_pid(raw_buf)))
	{
		if (psh->fn_detect(psh, raw_buf, nlen))
		{
			nEncoder = psm->fn_get_video_encoder(psm);
			return psh->fn_is_keyframe(psh, nEncoder);
		}
	}
	return 0;
}

int ts_is_keyframe(void *hdl, uint8_t *buff, int len)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)hdl;
	TS_PSI_MGR *psm = psh->pPSIHdl;
	int key = 0, n = 0;

	while (n + TS_SIZE <= len)
	{
		if (psh->fn_set_pat_pmt(psh, (char *)buff + n, TS_SIZE) >= 0)
		{
			key = psh->fn_set_pack(hdl, buff + n, TS_SIZE);
			if (key != 0)
				return key;
		}
		n += TS_SIZE;
	}
	return key;
}

int64_t ts_get_pts(void *hdl)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)hdl;
	return psh->fn_get_pts(hdl);
}

uint8_t *ts_get_pat(void *hdl)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)hdl;
	TS_PSI_MGR *psm = psh->pPSIHdl;
	return psm->pat->fn_get_cont(psm->pat);
}

uint8_t *ts_get_pmt(void *hdl)
{
	TS_StreamHandle *psh = (TS_StreamHandle *)hdl;
	TS_PSI_MGR *psm = psh->pPSIHdl;
	return psm->pmt->fn_get_cont(psm->pmt);
}