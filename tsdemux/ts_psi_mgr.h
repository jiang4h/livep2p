#ifndef  _TS_PSI_MGR_H
#define  _TS_PSI_MGR_H

#include <stdint.h>
#include "ts_psi_pat.h"
#include "ts_psi_pmt.h"

enum
{
	TS_VIDEO_POS,
	TS_AUDIO_POS
};

typedef struct ts_psi_mgr
{
	// attribute
	TS_PSI_PAT *pat;
	TS_PSI_PMT *pmt;
	TS_NodeInfo stream_index[32];

	// operation
	int(*fn_init)(void *self);
	int(*fn_set_pat_pmt)(void *self, uint8_t *buff, int nlen);
	int(*fn_is_ready)(void *self);
	uint8_t * (*fn_get_pat)(void *self);
	uint8_t * (*fn_get_pmt)(void *self);
	int(*fn_get_stream_type)(void *self, uint16_t pid, char *szInfo, uint16_t len);
	int(*fn_is_video)(void *self, uint16_t pid);
	uint16_t(*fn_get_video_encoder)(void *self);
} TS_PSI_MGR;

TS_PSI_MGR * ts_psi_get_manage();
void ts_psi_release_manage(TS_PSI_MGR *hdl);

#endif
