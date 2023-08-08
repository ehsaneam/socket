#include "header_decomp.h"

struct rohc_comp *compressor;
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

int compDecompTest()
{
    const char *payload = "Hello, Server!";
    unsigned char ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);
	/* the buffer that will contain the resulting ROHC packet */
	unsigned char rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
    rohc_status_t status;
    if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UNCOMPRESSED, 
                                  ROHC_PROFILE_IP, ROHC_PROFILE_TCP, -1))
	{
		PRINT_ERR_ROHC("failed to enable the IP/UDP and IP/UDP-Lite profiles\n");
		return -1;
	}
    rohc_buf_byte_at(ip_packet, 0) = 4 << 4; /* IP version 4 */
	rohc_buf_byte_at(ip_packet, 0) |= 5; /* IHL: min. IPv4 header length
	                                        (in 32-bit words) */
	rohc_buf_byte_at(ip_packet, 1) = 0; /* TOS */
	ip_packet.len = 5 * 4 + strlen(payload);
	rohc_buf_byte_at(ip_packet, 2) = (ip_packet.len >> 8) & 0xff; /* Total Length */
	rohc_buf_byte_at(ip_packet, 3) = ip_packet.len & 0xff;
	rohc_buf_byte_at(ip_packet, 4) = 0; /* IP-ID */
	rohc_buf_byte_at(ip_packet, 5) = 0;
	rohc_buf_byte_at(ip_packet, 6) = 0; /* Fragment Offset and IP flags */
	rohc_buf_byte_at(ip_packet, 7) = 0;
	rohc_buf_byte_at(ip_packet, 8) = 1; /* TTL */
	rohc_buf_byte_at(ip_packet, 9) = 134; /* Protocol: unassigned number */
	rohc_buf_byte_at(ip_packet, 10) = 0xa9; /* IP Checksum */
	rohc_buf_byte_at(ip_packet, 11) = 0x3f;
	rohc_buf_byte_at(ip_packet, 12) = 0x01; /* Source address */
	rohc_buf_byte_at(ip_packet, 13) = 0x02;
	rohc_buf_byte_at(ip_packet, 14) = 0x03;
	rohc_buf_byte_at(ip_packet, 15) = 0x04;
	rohc_buf_byte_at(ip_packet, 16) = 0x05; /* Destination address */
	rohc_buf_byte_at(ip_packet, 17) = 0x06;
	rohc_buf_byte_at(ip_packet, 18) = 0x07;
	rohc_buf_byte_at(ip_packet, 19) = 0x08;
    memcpy(rohc_buf_data_at(ip_packet, 5 * 4), payload, strlen(payload));
    dumpPacket((unsigned char*)ip_buffer, ip_packet.len, "1-buffer");
    status = rohc_compress4(compressor, ip_packet, &rohc_packet);
    dumpPacket((unsigned char*)rohc_buffer, rohc_packet.len, "1-compressed buffer");
    if(status == ROHC_STATUS_OK)
	{
        PRINT_INFO_ROHC("compression ok\n");
    }
    else
    {
        return -1;
    }
    unsigned char decomp_buffer[BUFFER_SIZE];
	struct rohc_buf decomp_packet = rohc_buf_init_empty(decomp_buffer, BUFFER_SIZE);
    struct rohc_buf *rcvd_feedback = NULL;
	struct rohc_buf *feedback_send = NULL;
    if( initDecompressor(ROHC_LARGE_CID)<0 )
    {
        exit(EXIT_FAILURE);
    }
	if(!rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UNCOMPRESSED, 
                                  ROHC_PROFILE_IP, ROHC_PROFILE_TCP, -1))
	{
		PRINT_ERR_ROHC("failed to enable the IP/UDP and IP/UDP-Lite profiles\n");
		return -1;
	}
    status = rohc_decompress3(decompressor, rohc_packet, &decomp_packet,
	                          rcvd_feedback, feedback_send);
    dumpPacket((unsigned char*)decomp_buffer, decomp_packet.len, "1-uncompressed buffer");
    if( status==ROHC_STATUS_OK )
	{
        if(!rohc_buf_is_empty(ip_packet))
		{
            PRINT_INFO_ROHC("decompression ok\n");
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    if( !memcmp(ip_buffer, decomp_buffer, decomp_packet.len) &&
        decomp_packet.len==ip_packet.len )
    {
        PRINT_INFO_ROHC("comp=decomp\n");
    }
    else
    {
        return -1;
    }
    return 0;
}

int compDecompTest2(unsigned char *ip_buffer, int ip_len)
{
    const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	struct rohc_buf ip_packet = rohc_buf_init_full(ip_buffer, ip_len, arrival_time);
	/* the buffer that will contain the resulting ROHC packet */
	unsigned char rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
    rohc_status_t status;
    if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UNCOMPRESSED, 
                                  ROHC_PROFILE_IP, ROHC_PROFILE_TCP, -1))
	{
		PRINT_ERR_ROHC("failed to enable the IP/TCP profiles\n");
		return -1;
	}
    status = rohc_compress4(compressor, ip_packet, &rohc_packet);
    if(status == ROHC_STATUS_OK)
	{
        PRINT_INFO_ROHC("compression ok\n");
    }
    else
    {
        return -1;
    }
    unsigned char decomp_buffer[BUFFER_SIZE];
	struct rohc_buf decomp_packet = rohc_buf_init_empty(decomp_buffer, BUFFER_SIZE);
    struct rohc_buf *rcvd_feedback = NULL;
	struct rohc_buf *feedback_send = NULL;
    if( initDecompressor(ROHC_LARGE_CID)<0 )
    {
        exit(EXIT_FAILURE);
    }
	if(!rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UNCOMPRESSED, 
                                  ROHC_PROFILE_IP, ROHC_PROFILE_TCP, -1))
	{
		PRINT_ERR_ROHC("failed to enable the IP/TCP profiles\n");
		return -1;
	}
    status = rohc_decompress3(decompressor, rohc_packet, &decomp_packet,
	                          rcvd_feedback, feedback_send);
    if( status==ROHC_STATUS_OK )
	{
        if(!rohc_buf_is_empty(ip_packet))
		{
            PRINT_INFO_ROHC("decompression ok\n");
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    if( !memcmp(ip_buffer, decomp_buffer, decomp_packet.len) &&
        decomp_packet.len==ip_packet.len )
    {
        PRINT_INFO_ROHC("comp=decomp\n");
    }
    else
    {
        return -1;
    }
    releaseDecompressor();
    dumpPacket(ip_buffer, ip_packet.len, "ip");
    dumpPacket(rohc_buffer, rohc_packet.len, "comp");
    dumpPacket(decomp_buffer, decomp_packet.len, "decomp");
    return 0;
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

void releaseCompressor()
{
    if( compressor!=NULL )
    {
        rohc_comp_free(compressor);
    }
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