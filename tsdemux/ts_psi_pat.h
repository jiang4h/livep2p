#ifndef  _TS_PSI_PAT_H
#define  _TS_PSI_PAT_H

#include <stdint.h>

typedef struct ts_psi_pat
{
	// attribute
	uint16_t nCC;
	uint8_t buff[256];
	uint16_t nPMTCount;
	uint16_t pmt_id_arr[32];

	// operation
	int(*fn_init)(void *self);
	int(*fn_set_cont)(void *self, uint8_t *buff, int len);
	uint8_t * (*fn_get_cont)(void *self);
	uint16_t(*fn_get_pmt_count)(void *self);
	uint16_t(*fn_get_pmt_id)(void *self, int num);

} TS_PSI_PAT;

TS_PSI_PAT * ts_psi_pat_get_handle();
void ts_psi_pat_close_handle(TS_PSI_PAT *hdl);

#endif
