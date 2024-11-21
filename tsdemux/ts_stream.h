#ifndef _TS_STREAM_H
#define _TS_STREAM_H

#include <stdint.h>
#include "ts.h"
#include "ts_psi_mgr.h"

typedef struct ts_stream_handle
{
    // attribute
    int64_t nPTS;
    uint8_t *pBuff;
    uint8_t *pPayload;
    int nLength;
    uint8_t nPesLen;
	TS_PSI_MGR *pPSIHdl;

    // operation
    int (*fn_init)(void *self);
    int (*fn_detect)(void *self, uint8_t *buff, int nlen);
    int (*fn_is_keyframe)(void *self, uint16_t enc_type);
    int64_t (*fn_get_pts)(void *self);
	int (*fn_set_pat_pmt)(void *self, char *buf, int nlen);
	int (*fn_set_pack)(void *self, void *raw_buf, int nlen);
} TS_StreamHandle;

TS_StreamHandle *ts_stream_get_handle();
void ts_stream_close_handle(TS_StreamHandle *hdl);
int ts_is_keyframe(void *hdl, uint8_t *buff, int len);
int64_t ts_get_pts(void *hdl);
uint8_t *ts_get_pat(void *hdl);
uint8_t *ts_get_pmt(void *hdl);

#endif
