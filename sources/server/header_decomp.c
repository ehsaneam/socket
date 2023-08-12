#include "header_decomp.h"

struct rohc_decomp *decompressor;
int rohc_verbose = DBG_ERROR;

#define PRINT_ERR_ROHC(fmt, ...) \
    if( rohc_verbose>=DBG_ERROR ) \
        fprintf(stderr, "[ROHC] [ERROR] " fmt, ##__VA_ARGS__)

#define PRINT_WARN_ROHC(fmt, ...) \
    if( rohc_verbose>=DBG_WARNING ) \
        fprintf(stderr, "[ROHC] [WARNING] " fmt, ##__VA_ARGS__)

#define PRINT_INFO_ROHC(fmt, ...) \
    if( rohc_verbose>=DBG_INFO ) \
        fprintf(stderr, "[ROHC] [INFO] " fmt, ##__VA_ARGS__)

int decompressPacket(unsigned char *rohc_buffer, int rohc_len, unsigned char *ip_buffer)
{
    /* the buffer that will contain the ROHC packet to decompress */
    const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
    struct rohc_buf rohc_packet = rohc_buf_init_full(rohc_buffer, rohc_len, arrival_time);

    /* the buffer that will contain the resulting IP packet */
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);

    rohc_status_t status;

    /* Now, decompress the ROHC packet */
    status = rohc_decompress3(decompressor, rohc_packet, &ip_packet,
	                          NULL, NULL);

    if( status!=ROHC_STATUS_OK )
	{
        PRINT_WARN_ROHC("failed to decompress IP packet %d\n", status);
        return -1;
    }
    else if( rohc_buf_is_empty(ip_packet) )
    {
        PRINT_WARN_ROHC("no IP packet decompressed\n");
        return 0;
    }
    return ip_packet.len;
}

int initDecompressor(rohc_cid_type_t rohc_cid_type)
{
    /* Create a ROHC decompressor to operate:
	 *  - with large CIDs,
	 *  - with the maximum of 5 streams (MAX_CID = 4),
	 *  - in Unidirectional mode (U-mode).
	 */
    if( rohc_cid_type==ROHC_LARGE_CID )
    {
        decompressor = rohc_decomp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, 
                                ROHC_U_MODE);
    }
    else if( rohc_cid_type==ROHC_SMALL_CID )
    {
        decompressor = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
                                ROHC_U_MODE);
    }
    else
    {
        PRINT_ERR_ROHC("rohc cid type is wrong\n");
        return -1;
    }

	if( decompressor==NULL )
	{
		PRINT_ERR_ROHC("failed create the ROHC decompressor\n");
		return -1;
	}

    /* Enable the decompression profiles you need */
	if( !rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UNCOMPRESSED, 
                                ROHC_PROFILE_IP, ROHC_PROFILE_TCP, -1) )
	{
		PRINT_ERR_ROHC("failed to enable the TCP/IP profile\n");
		releaseDecompressor();
        return DECOMP_FAILED;
	}

    if( rohc_verbose>=DBG_INFO )
    {    
        if( !rohc_decomp_set_traces_cb2(decompressor, print_rohc_traces, NULL) )
        {
            PRINT_ERR_ROHC("failed to set the callback for traces on decompressor\n");
            return -1;
        }
    }
    return 0;
}

void releaseDecompressor()
{
    if( decompressor!=NULL )
    {
        rohc_decomp_free(decompressor);
    }
}

void print_rohc_traces(void *const priv_ctxt __attribute__((unused)),
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	va_list args;
    assert(level>=0 && entity>=0 && profile>-1);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void setRohcVerbose(int verbose_level)
{
    rohc_verbose = verbose_level;
}