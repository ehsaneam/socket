#ifndef __HEADER_COMP_H__
#define __HEADER_COMP_H__

#include "rohc.h"
#include "rohc_comp.h"
#include "rohc_decomp.h"
#include "config.h"
#include "common.h"

#define BUFFER_SIZE     2048
#define DECOMP_FAILED   -2

int compDecompTest();
int compDecompTest2(unsigned char *ip_buffer, int ip_len);
int initCompressor(rohc_cid_type_t rohc_cid_type);
int initDecompressor(rohc_cid_type_t rohc_cid_type);
void releaseCompressor();
void releaseDecompressor();
void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));
int genRandNum(const struct rohc_comp *const comp,
                          void *const user_context);
void setRohcVerbose();

#endif //__HEADER_COMP_H__