#include	<stdio.h>
#include	<stdlib.h>
#include	"pat.h"
#include	"ts_psi_pat.h"

// declaration
// member function
static int fn_init(void *self);
static int fn_set_cont(void *self, uint8_t *buff, int len);
static uint8_t * fn_get_cont(void *self);
static uint16_t  fn_get_pmt_count(void *self);
static uint16_t  fn_get_pmt_id(void *self, int num);
// private function
static int sf_pat_validate(uint8_t *buff);
static uint16_t sf_get_pmt_pid(uint8_t *PAT, uint16_t pmt_arr[]);
static int sf_compare_pmt_pid(TS_PSI_PAT *pat, uint8_t *buff);
// end

// implementation
TS_PSI_PAT * ts_psi_pat_get_handle()
{
	TS_PSI_PAT *hdl = (TS_PSI_PAT *)malloc(sizeof(TS_PSI_PAT));
	hdl->fn_init = fn_init;
	hdl->fn_get_cont = fn_get_cont;
	hdl->fn_set_cont = fn_set_cont;
	hdl->fn_get_pmt_count = fn_get_pmt_count;
	hdl->fn_get_pmt_id = fn_get_pmt_id;

	return hdl;
}

void ts_psi_pat_close_handle(TS_PSI_PAT *hdl)
{
	if (hdl)
	{
		free(hdl);
	}
}

static int fn_init(void *self)
{
	TS_PSI_PAT *pat = (TS_PSI_PAT *)self;

	pat->nCC = 0;
	pat->nPMTCount = 0;
	memset(pat->buff, 0, 256);

	return 0;
}

static int fn_set_cont(void *self, uint8_t *buff, int len)
{
	TS_PSI_PAT *pat = (TS_PSI_PAT *)self;
	int nret = 0;

	if (sf_pat_validate(buff))
	{
		if (pat->nPMTCount > 0)
		{
			nret = sf_compare_pmt_pid(pat, buff);
		}
		else
		{
			pat->nPMTCount = sf_get_pmt_pid(buff, pat->pmt_id_arr);
			memcpy(pat->buff, buff, TS_SIZE);
			/*for (int i = 0; i < pat->nPMTCount; i++)
			{
				printf ( "INIT PAT, %d pmt id: %X\n", i, pat->pmt_id_arr[i] );
			}*/
		}
	}
	else
	{
		nret = -1;
	}

	return nret;
}

static int sf_pat_validate(uint8_t *buff)
{
	int bRet = 0;

	if (ts_get_pid(buff) == PAT_PID)
	{
		uint8_t *ptr = ts_section(buff);
		if (ptr)
		{
			bRet = pat_validate(ptr);
		}
		else
		{
			//printf ( "PID is 0 but the data is not pat\n" );
		}
	}

	return bRet;
}

static uint16_t sf_get_pmt_pid(uint8_t *PAT, uint16_t pmt_arr[])
{
	if (!PAT) return 0;

	uint16_t i = 0;
	uint8_t *pSection = ts_section(PAT);

	if (!pSection) return 0;
	uint8_t *pmt_sec = pat_get_program(pSection, i);

	while (pmt_sec != NULL)
	{
		pmt_arr[i] = patn_get_pid(pmt_sec);
		i++;
		pmt_sec = pat_get_program(pSection, i);
	}

	return i;
}

static int sf_compare_pmt_pid(TS_PSI_PAT *pat, uint8_t *buff)
{
	int bret = -1;
	int nTempCount = 0;
	uint16_t temp_arr[32];
	int i;

	if (!pat || !buff) return -1;

	nTempCount = sf_get_pmt_pid(buff, temp_arr);
	if (nTempCount <= 0)
	{
		return bret;
	}
	else if (nTempCount != pat->nPMTCount)
	{
		memcpy(pat->buff, buff, TS_SIZE);
		pat->nPMTCount = nTempCount;
		bret = 0;
		return bret;
	}
	else
	{
		for (i = 0; i < nTempCount; i++)
		{
			if (pat->pmt_id_arr[i] != temp_arr[i])
			{
				//printf("PAT is not same\n");
				pat->nPMTCount = sf_get_pmt_pid(buff, pat->pmt_id_arr);
				memcpy(pat->buff, buff, TS_SIZE);
				bret = 0;
				break;
			}
			else
			{
				bret = 1;
			}
		}
	}

	return bret;
}

static uint8_t * fn_get_cont(void *self)
{
	TS_PSI_PAT *pat = (TS_PSI_PAT *)self;
	uint8_t *ptr = NULL;

	if (ts_validate(pat->buff))
	{
		ptr = pat->buff;
	}

	return ptr;
}

static uint16_t fn_get_pmt_count(void *self)
{
	TS_PSI_PAT *pat = (TS_PSI_PAT *)self;

	return pat->nPMTCount;
}

static uint16_t fn_get_pmt_id(void *self, int num)
{
	TS_PSI_PAT *pat = (TS_PSI_PAT *)self;
	if (num < 0 || num >= 32) return 0;
	return pat->pmt_id_arr[num];
}

