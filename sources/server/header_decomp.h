#ifndef __HEADER_COMP_H__
#define __HEADER_COMP_H__

#include "rohc.h"
#include "rohc_decomp.h"
#include "config.h"
#include "common.h"

#define BUFFER_SIZE     2048
#define DECOMP_FAILED   -2

#define DBG_INFO        3
#define DBG_WARNING     2
#define DBG_ERROR       1

int decompressPacket(unsigned char *rohc_buffer, int rohc_len, 
                    unsigned char *ip_buffer);
int initDecompressor(rohc_cid_type_t rohc_cid_type);
void releaseDecompressor();
void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));
void setRohcVerbose();

#endif //__HEADER_COMP_H__