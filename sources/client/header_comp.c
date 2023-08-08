#include "header_comp.h"

struct rohc_comp *compressor;
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


int compressPacket(unsigned char *ip_buffer, int ip_len, unsigned char *rohc_buffer)
{
	rohc_status_t status;

    /* the packet that will contain the IPv4 packet to compress */
    const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	struct rohc_buf ip_packet = rohc_buf_init_full(ip_buffer, ip_len, arrival_time);

    /* the packet that will contain the resulting ROHC packet */
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);

    /* Now, compress IP packet */
    status = rohc_compress4(compressor, ip_packet, &rohc_packet);

    if( status==ROHC_STATUS_SEGMENT )
	{
        PRINT_ERR_ROHC("resulting ROHC packet was too large for the MRRU "
                        "configured. rohc_packet buffer contains the first "
                        "ROHC segment. but we didnt support retrieving"
                        "ROHC segments.\n");
        return -1;
    }
    else if( status==ROHC_STATUS_OK )
	{
        return rohc_packet.len; 
    }
    else
	{
        PRINT_ERR_ROHC("compression of fake IP packet failed\n");
        return -1;
    }
}

int initCompressor(rohc_cid_type_t rohc_cid_type)
{
    unsigned int seed = (unsigned int) time(NULL);
	srand(seed);
    /* Create a ROHC compressor with small CIDs and the largest MAX_CID
	 * possible for small CIDs */
    if( rohc_cid_type==ROHC_LARGE_CID )
    {
        compressor = rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX,
	                            genRandNum, NULL);
    }
    else if( rohc_cid_type==ROHC_SMALL_CID )
    {
        compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                            genRandNum, NULL);
    }
    else
    {
        PRINT_ERR_ROHC("rohc cid type is wrong\n");
        return -1;
    }
    
    if( compressor==NULL )
	{
		PRINT_ERR_ROHC("failed create the ROHC compressor\n");
		return -1;
	}

    /* Enable the compression profiles you need */
	PRINT_INFO_ROHC("enable ROHC compression profile\n");
    if( !rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UNCOMPRESSED, 
                                ROHC_PROFILE_IP, ROHC_PROFILE_TCP, -1) )
	{
		PRINT_ERR_ROHC("failed to enable the TCP/IP profile\n");
		releaseCompressor();
        return -1;
	}

    if( rohc_verbose>=DBG_INFO )
    {
        if( !rohc_comp_set_traces_cb2(compressor, print_rohc_traces, NULL) )
        {
            PRINT_ERR_ROHC("failed to set the callback for traces on compressor\n");
            return -1;
        }
    }
    return 0;
}

void releaseCompressor()
{
    if( compressor!=NULL )
    {
        rohc_comp_free(compressor);
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

int genRandNum(const struct rohc_comp *const comp,
                          void *const user_context)
{
    assert(comp!=NULL);
    assert(user_context==NULL);
	return rand();
}

void setRohcVerbose(int verbose_level)
{
    rohc_verbose = verbose_level;
}