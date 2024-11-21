#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "pmt.h"
#include "ts.h"
#include "ts_psi_pmt.h"

// declaration
// member function
static int fn_init(void *self);
static int fn_set_cont(void *self, uint8_t *buff, int len);
static uint8_t * fn_get_cont(void *self);
static int fn_set_pmt_id(void *self, uint16_t pid);
static uint16_t fn_get_stream_type(void *self, uint16_t pid, char *desc, int len);
static TS_NodeInfo fn_get_stream_id(void *self, uint16_t type);
// private function
static int sf_get_stream_info(TS_PMTNode *node, uint8_t *buff);
static int sf_compare_pmt_data(TS_PMTNode *node, uint8_t *buff);
// end

// implementation
TS_PSI_PMT * ts_psi_pmt_get_handle()
{
	TS_PSI_PMT *hdl = (TS_PSI_PMT *)malloc(sizeof(TS_PSI_PMT));
	hdl->fn_init = fn_init;
	hdl->fn_set_cont = fn_set_cont;
	hdl->fn_get_cont = fn_get_cont;
	hdl->fn_set_pmt_id = fn_set_pmt_id;
	hdl->fn_get_stream_type = fn_get_stream_type;
	hdl->fn_get_stream_id = fn_get_stream_id;

	return hdl;
}

void ts_psi_pmt_close_handle(TS_PSI_PMT *hdl)
{
	if (hdl)
	{
		free(hdl);
	}
}

static int fn_init(void *self)
{
	TS_PSI_PMT *pmt = (TS_PSI_PMT *)self;

	memset(&pmt->mNode, 0, sizeof(TS_PMTNode));

	return 0;
}

static int fn_set_cont(void *self, uint8_t *buff, int len)
{
	TS_PSI_PMT *pmt = (TS_PSI_PMT *)self;

	if (len != TS_SIZE) return -1;
	if (ts_get_pid(buff) == pmt->mNode.pmt_id)
	{
		if (pmt->mNode.nStreamCount <= 0)
		{
			sf_get_stream_info(&pmt->mNode, buff);
			memcpy(pmt->mNode.buff, buff, TS_SIZE);
			/*for (int i = 0; i < pmt->mNode.nStreamCount; i++)
			{
				printf("INIT pmt, stream id: %04X, stream type: %02X, %s\n",
					pmt->mNode.stream_id[i], pmt->mNode.stream_Type[i],
					pmt_get_streamtype_txt(pmt->mNode.stream_Type[i]));
			}*/
		}
		else
		{
			sf_compare_pmt_data(&pmt->mNode, buff);
		}
	}

	return 0;
}
static int sf_compare_pmt_data(TS_PMTNode *node, uint8_t *buff)
{
	TS_PMTNode temp_node;
	int i;

	memset(&temp_node, 0, sizeof(TS_PMTNode));

	if (sf_get_stream_info(&temp_node, buff))
	{
		if (temp_node.nStreamCount != node->nStreamCount)
		{
			memcpy(node->buff, buff, TS_SIZE);
			sf_get_stream_info(node, buff);
		}
		else
		{
			for (i = 0; i < temp_node.nStreamCount; i++)
			{
				if (temp_node.stream_id[i] != node->stream_id[i])
				{
					memcpy(node->buff, buff, TS_SIZE);
					sf_get_stream_info(node, buff);
					break;
				}
			}
		}
	}

	return 0;
}

static int sf_get_stream_info(TS_PMTNode *node, uint8_t *buff)
{
	int nret = 0;

	uint8_t *ptr = ts_section(buff);
	if (pmt_validate(ptr))
	{
		int i = 0;
		uint8_t *es = pmt_get_es(ptr, i);

		while (es != NULL)
		{
			if (pmt_validate_es(ptr, es, pmtn_get_desclength(es)))
			{
				node->stream_id[i] = pmtn_get_pid(es);
				node->stream_Type[i] = pmtn_get_streamtype(es);
			}

			i++;
			es = pmt_get_es(ptr, i);
			nret = 1;
		}

		node->nStreamCount = i;
	}

	return nret;
}
static uint8_t * fn_get_cont(void *self)
{
	TS_PSI_PMT *pmt = (TS_PSI_PMT *)self;
	uint8_t *ptr = NULL;

	if (ts_validate(pmt->mNode.buff))
	{
		ptr = pmt->mNode.buff;
	}

	return ptr;
}

static int fn_set_pmt_id(void *self, uint16_t pid)
{
	TS_PSI_PMT *pmt = (TS_PSI_PMT *)self;

	pmt->mNode.pmt_id = pid;

	return 0;
}

static uint16_t fn_get_stream_type(void *self, uint16_t pid, char *desc, int len)
{

	TS_PSI_PMT *pmt = (TS_PSI_PMT *)self;
	uint16_t nret = TS_MEDIA_TYPE_UNKONWN;
	int i;

	if (!desc || len <= 0) return 0;

	for (i = 0; i < pmt->mNode.nStreamCount; i++)
	{
		if (pmt->mNode.stream_id[i] == pid)
		{
			snprintf(desc, len, "%s", pmt_get_streamtype_txt(pmt->mNode.stream_Type[i]));
			nret = TS_MEDIA_TYPE_VIDEO;
			break;
		}
	}

	return nret;
}

#ifdef _WIN32
static char *strcasestr(const char *haystack, const char *needle)
{
	size_t length_needle;
	size_t length_haystack;
	size_t i;

	if (!haystack || !needle)
		return NULL;

	length_needle = strlen(needle);
	length_haystack = strlen(haystack);
	if (length_haystack < length_needle) return NULL;
	length_haystack = length_haystack - length_needle + 1;

	for (i = 0; i < length_haystack; i++)
	{
		size_t j;

		for (j = 0; j < length_needle; j++)
		{
			unsigned char c1;
			unsigned char c2;

			c1 = haystack[i + j];
			c2 = needle[j];
			if (toupper(c1) != toupper(c2))
				goto next;
		}
		return (char *)haystack + i; next:;
	}

	return NULL;
}
#endif

static TS_NodeInfo fn_get_stream_id(void *self, uint16_t type)
{
	TS_PSI_PMT *pmt = (TS_PSI_PMT *)self;
	char szType[32] = { 0 };
	TS_NodeInfo node;
	int i;

	node.pid = 0;
	node.enc_type = 0;

	switch (type)
	{
	case TS_MEDIA_TYPE_PAT:
		break;

	case TS_MEDIA_TYPE_PMT:
		break;

	case TS_MEDIA_TYPE_VIDEO:
		snprintf(szType, 32, "video");
		break;

	case TS_MEDIA_TYPE_AUDIO:
		snprintf(szType, 32, "audio");
		break;
	}

	for (i = 0; i < pmt->mNode.nStreamCount; i++)
	{
		if (strcasestr(pmt_get_streamtype_txt(pmt->mNode.stream_Type[i]), szType) != NULL)
		{
			node.pid = pmt->mNode.stream_id[i];
			switch (pmt->mNode.stream_Type[i])
			{
			case 0x1B:
				node.enc_type = TS_STREAM_H264;
				break;

			case 0x24:
				node.enc_type = TS_STREAM_H265;
				break;

			case 0x02:
				node.enc_type = TS_STREAM_MPEG2;
				break;

			case 0x42:
				node.enc_type = TS_STREAM_CAVS;
				break;
			}
			break;
		}
	}

	return node;
}

