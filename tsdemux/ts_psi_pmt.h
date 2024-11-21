#ifndef  _TS_PSI_PMT_H
#define  _TS_PSI_PMT_H

#include <stdint.h>

enum
{
	TS_MEDIA_TYPE_PAT,
	TS_MEDIA_TYPE_PMT,
	TS_MEDIA_TYPE_VIDEO,
	TS_MEDIA_TYPE_AUDIO,
	TS_MEDIA_TYPE_UNKONWN
};

enum
{
	TS_STREAM_UNKONWN,
	TS_STREAM_H264,
	TS_STREAM_H265,
	TS_STREAM_MPEG2,
	TS_STREAM_CAVS
};

typedef struct ts_node_info
{
	uint16_t pid;
	uint16_t enc_type;
} TS_NodeInfo;

typedef struct ts_pmt_node
{
	// attribute
	uint16_t pmt_id;
	uint8_t  pmt_cc;
	uint8_t  buff[256];
	uint16_t nStreamCount;
	uint16_t stream_id[32];
	uint8_t  stream_Type[32];
} TS_PMTNode;

typedef struct ts_psi_pmt_t
{
	// attribute
	TS_PMTNode mNode;

	// operation
	int (*fn_init)(void *self);
	int (*fn_set_cont)(void *self, uint8_t *buff, int len);
	uint8_t *(*fn_get_cont)(void *self);
	int (*fn_set_pmt_id)(void *self, uint16_t pid);
	uint16_t (*fn_get_stream_type)(void *self, uint16_t pid, char *desc, int len);
	TS_NodeInfo (*fn_get_stream_id)(void *self, uint16_t type);

} TS_PSI_PMT;

TS_PSI_PMT * ts_psi_pmt_get_handle();
void ts_psi_pmt_close_handle(TS_PSI_PMT *hdl);

#endif
