/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2013 Friedrich
 * Copyright 2009,2010 Thales Communications
 * Copyright 2007,2009,2010,2012,2013,2014,2017 Viveris Technologies
 * Copyright 2012 WBX
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file rohc_comp.c
 * @brief ROHC compression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_comp  The ROHC compression API
 *
 * The compression API of the ROHC library allows a program to compress the
 * protocol headers of some uncompressed packets into ROHC packets.
 *
 * The program shall first create a compressor context and configure it. It
 * then may compress as many packets as needed. When done, the ROHC compressor
 * context shall be destroyed.
 */

#include "rohc_comp.h"
#include "rohc_comp_internals.h"
#include "rohc_packets.h"
#include "rohc_traces.h"
#include "rohc_traces_internal.h"
#include "rohc_time_internal.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "rohc_add_cid.h"
#include "rohc_bit_ops.h"
#include "ip.h"
#include "crc.h"
#include "udp.h"
#include "ip_numbers.h"
#include "c_tcp_defines.h"

#include "config.h" /* for PACKAGE_(NAME|URL|VERSION) */

#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

extern const struct rohc_comp_profile c_udp_profile;
extern const struct rohc_comp_profile c_tcp_profile;
extern const struct rohc_comp_profile c_ip_profile;
extern const struct rohc_comp_profile c_uncompressed_profile;

/**
 * @brief The compression parts of the ROHC profiles.
 *
 * The order of profiles declaration is important: they are evaluated in that
 * order. The RTP profile shall be declared before the UDP one for example.
 */
static const struct rohc_comp_profile *const rohc_comp_profiles[C_NUM_PROFILES] =
{
	&c_udp_profile,  /* must be declared after RTP profile */
	&c_tcp_profile,
	&c_ip_profile,  /* must be declared after all IP-based profiles */
	&c_uncompressed_profile, /* must be declared last */
};

/*
 * Prototypes of private functions related to ROHC compression profiles
 */

static const struct rohc_comp_profile *
	rohc_get_profile_from_id(const struct rohc_comp *comp,
	                         const rohc_profile_t profile_id)
	__attribute__((warn_unused_result, nonnull(1)));

static const struct rohc_comp_profile *
	c_get_profile_from_packet(const struct rohc_comp *const comp,
	                          const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

/*
 * Prototypes of private functions related to ROHC compression contexts
 */

static bool c_create_contexts(struct rohc_comp *const comp)
	__attribute__((nonnull(1)));
static void c_destroy_contexts(struct rohc_comp *const comp)
	__attribute__((nonnull(1)));

static struct rohc_comp_ctxt *
	c_create_context(struct rohc_comp *const comp,
	                 const struct rohc_comp_profile *const profile,
	                 const struct net_pkt *const packet,
	                 const struct rohc_ts arrival_time,
	                 const bool do_ctxt_replication,
	                 const rohc_cid_t cid_for_replication)
	__attribute__((nonnull(1, 2, 3), warn_unused_result));
static struct rohc_comp_ctxt *
	rohc_comp_find_ctxt(struct rohc_comp *const comp,
	                    const struct net_pkt *const packet,
	                    const int profile_id_hint,
	                    const struct rohc_ts arrival_time)
	__attribute__((nonnull(1, 2), warn_unused_result));

/*
 * Definitions of public functions
 */

/**
 * @brief Create a new ROHC compressor
 *
 * Create a new ROHC compressor with the given type of CIDs and MAX_CID.
 *
 * The user-defined callback for random numbers is called by the ROHC library
 * every time a new random number is required. It currently happens only to
 * initiate the Sequence Number (SN) of new IP-only, IP/UDP, or IP/UDP-Lite
 * streams to a random value as defined by RFC 3095.
 *
 * @param cid_type  The type of Context IDs (CID) that the ROHC compressor
 *                  shall operate with.
 *                  Accepted values are:
 *                    \li \ref ROHC_SMALL_CID for small CIDs
 *                    \li \ref ROHC_LARGE_CID for large CIDs
 * @param max_cid   The maximum value that the ROHC compressor should use for
 *                  context IDs (CID). As CIDs starts with value 0, the number
 *                  of contexts is \e max_cid + 1. \n
 *                  Accepted values are:
 *                    \li [0, \ref ROHC_SMALL_CID_MAX] if \e cid_type is
 *                        \ref ROHC_SMALL_CID
 *                    \li [0, \ref ROHC_LARGE_CID_MAX] if \e cid_type is
 *                        \ref ROHC_LARGE_CID
 * @param rand_cb   The random callback to set
 * @param rand_priv Private data that will be given to the callback, may be
 *                  used as a context by user
 * @return          The created compressor if successful,
 *                  NULL if creation failed
 *
 * @warning Don't forget to free compressor memory with \ref rohc_comp_free
 *          if \e rohc_comp_new2 succeeded
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_free
 * @see rohc_compress4
 * @see rohc_comp_set_traces_cb2
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_enable_profile
 * @see rohc_comp_disable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_set_mrru
 * @see rohc_comp_set_wlsb_window_width
 * @see rohc_comp_set_periodic_refreshes
 * @see rohc_comp_set_rtp_detection_cb
 */
struct rohc_comp * rohc_comp_new2(const rohc_cid_type_t cid_type,
                                  const rohc_cid_t max_cid,
                                  const rohc_comp_random_cb_t rand_cb,
                                  void *const rand_priv)
{
	const size_t wlsb_width = 4; /* default window width for W-LSB encoding */
	struct rohc_comp *comp;
	bool is_fine;
	size_t i;

	/* check input parameters */
	if(cid_type == ROHC_SMALL_CID)
	{
		/* use small CIDs in range [0, ROHC_SMALL_CID_MAX] */
		if(max_cid > ROHC_SMALL_CID_MAX)
		{
			goto error;
		}
	}
	else
	{
		/* unexpected CID type */
		goto error;
	}
	if(rand_cb == NULL)
	{
		return NULL;
	}

	/* allocate memory for the ROHC compressor */
	comp = calloc(1, sizeof(struct rohc_comp));
	if(comp == NULL)
	{
		goto error;
	}

	comp->medium.cid_type = cid_type;
	comp->medium.max_cid = max_cid;
	comp->random_cb = rand_cb;
	comp->random_cb_ctxt = rand_priv;

	/* all compression profiles are disabled by default */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		comp->enabled_profiles[i] = false;
	}

	/* reset statistics */
	comp->num_packets = 0;
	comp->total_compressed_size = 0;
	comp->total_uncompressed_size = 0;
	comp->last_context = NULL;

	/* set the default W-LSB window width */
	is_fine = rohc_comp_set_wlsb_window_width(comp, wlsb_width);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* set the default timeouts for periodic refreshes of contexts */
	is_fine = rohc_comp_set_periodic_refreshes(comp,
	                                           CHANGE_TO_IR_COUNT,
	                                           CHANGE_TO_FO_COUNT);
	if(is_fine != true)
	{
		goto destroy_comp;
	}
	is_fine = rohc_comp_set_periodic_refreshes_time(comp,
	                                                CHANGE_TO_IR_TIME,
	                                                CHANGE_TO_FO_TIME);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* init the tables for fast CRC computation */
	rohc_crc_init_table(comp->crc_table_3, ROHC_CRC_TYPE_3);
	rohc_crc_init_table(comp->crc_table_7, ROHC_CRC_TYPE_7);
	rohc_crc_init_table(comp->crc_table_8, ROHC_CRC_TYPE_8);

	/* create the MAX_CID + 1 contexts */
	if(!c_create_contexts(comp))
	{
		goto destroy_comp;
	}

	return comp;

destroy_comp:
	zfree(comp);
error:
	return NULL;
}

/**
 * @brief Destroy the given ROHC compressor
 *
 * Destroy a ROHC compressor that was successfully created with
 * \ref rohc_comp_new2
 *
 * @param comp  The ROHC compressor to destroy
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_new2
 */
void rohc_comp_free(struct rohc_comp *const comp)
{
	if(comp != NULL)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "free ROHC compressor");

		/* free memory used by contexts */
		c_destroy_contexts(comp);

		/* free the compressor */
		free(comp);
	}
}

/**
 * @brief Set the callback function used to manage traces in compressor
 *
 * Set the user-defined callback function used to manage traces in the
 * compressor.
 *
 * The function will be called by the ROHC library every time it wants to
 * print something related to compression, from errors to debug. User may
 * thus decide what traces are interesting (filter on \e level, source
 * \e entity, or \e profile) and what to do with them (print on console,
 * storage in file, syslog...).
 *
 * @warning The callback can not be modified after library initialization
 *
 * @param comp       The ROHC compressor
 * @param callback   Two possible cases:
 *                     \li The callback function used to manage traces
 *                     \li NULL to remove the previous callback
 * @param priv_ctxt  An optional private context, may be NULL
 * @return           true on success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet rtp_detection.c define compression traces callback
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet rtp_detection.c set compression traces callback
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 */
bool rohc_comp_set_traces_cb2(struct rohc_comp *const comp,
                              rohc_trace_callback2_t callback,
                              void *const priv_ctxt)
{
	/* check compressor validity */
	if(comp == NULL)
	{
		/* cannot print a trace without a valid compressor */
		goto error;
	}

	/* refuse to set a new trace callback if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "unable to "
		           "modify the trace callback after initialization");
		goto error;
	}

	/* replace current trace callback by the new one */
	comp->trace_callback = callback;
	comp->trace_callback_priv = priv_ctxt;

	return true;

error:
	return false;
}


/**
 * @brief Compress the given uncompressed packet into a ROHC packet
 *
 * Compress the given uncompressed packet into a ROHC packet. The compression
 * may succeed into two different ways:
 *   \li return \ref ROHC_STATUS_OK and a full ROHC packet,
 *   \li return \ref ROHC_STATUS_SEGMENT and no ROHC data if ROHC segmentation
 *       is required.
 *
 * Notes:
 *   \li ROHC segmentation:
 *       The ROHC compressor has to use ROHC segmentation if the output buffer
 *       rohc_packet was too small for the compressed ROHC packet and if the
 *       Maximum Reconstructed Reception Unit (MRRU) configured with the
 *       function \ref rohc_comp_set_mrru was not exceeded. If ROHC segmentation
 *       is used, one may use the \ref rohc_comp_get_segment2 function to
 *       retrieve all the ROHC segments one by one.
 *   \li Time-related features in the ROHC protocol:
 *       Set the \e uncomp_packet.time parameter to 0 if arrival time of the
 *       uncompressed packet is unknown or to disable the time-related features
 *       in the ROHC protocol.
 *
 * @param comp              The ROHC compressor
 * @param uncomp_packet     The uncompressed packet to compress
 * @param[out] rohc_packet  The resulting compressed ROHC packet
 * @return                  Possible return values:
 *                          \li \ref ROHC_STATUS_OK if a ROHC packet is
 *                              returned
 *                          \li \ref ROHC_STATUS_SEGMENT if no ROHC data is
 *                              returned and ROHC segments can be retrieved
 *                              with successive calls to
 *                              \ref rohc_comp_get_segment2
 *                          \li \ref ROHC_STATUS_OUTPUT_TOO_SMALL if the
 *                              output buffer is too small for the compressed
 *                              packet
 *                          \li \ref ROHC_STATUS_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \snippet simple_rohc_program.c define IP and ROHC packets
 * \code
	...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #1
 * \snippet simple_rohc_program.c compress IP packet #2
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #3
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #4
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #5
 * \code
	...
\endcode
 *
 * @see rohc_comp_set_mrru
 * @see rohc_comp_get_segment2
 */
rohc_status_t rohc_compress4(struct rohc_comp *const comp,
                             const struct rohc_buf uncomp_packet,
                             struct rohc_buf *const rohc_packet)
{
	struct net_pkt ip_pkt;
	struct rohc_comp_ctxt *c;
	rohc_packet_t packet_type;
	int rohc_hdr_size;
	size_t payload_size;
	size_t payload_offset;

	rohc_status_t status = ROHC_STATUS_ERROR; /* error status by default */

	//////////////////////////////////////////////////////////////////////////

	printf("len:%lu, sec:%lu, uncomp_data:", uncomp_packet.len, uncomp_packet.time.sec);
	for( size_t i=0 ; i<uncomp_packet.len ; i++ )
	{
		printf("%hhu ", uncomp_packet.data[i]);
	}

	//////////////////////////////////////////////////////////////////////////

	// getDiffTime(0);

	/* check inputs validity */
	if(comp == NULL)
	{
		goto error;
	}
	if(rohc_buf_is_malformed(uncomp_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is malformed");
		goto error;
	}
	if(rohc_buf_is_empty(uncomp_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is empty");
		goto error;
	}
	if(rohc_packet == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is NULL");
		goto error;
	}
	if(rohc_buf_is_malformed(*rohc_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is malformed");
		goto error;
	}
	if(!rohc_buf_is_empty(*rohc_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is not empty");
		goto error;
	}

	/* print uncompressed bytes */
	if((comp->features & ROHC_COMP_FEATURE_DUMP_PACKETS) != 0)
	{
		rohc_dump_packet(comp->trace_callback, comp->trace_callback_priv,
		                 ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
		                 "uncompressed data, max 100 bytes", uncomp_packet);
	}

	// printf("\ncheck-drop>>%d", getLDiffTime());

	/* parse the uncompressed packet */
	net_pkt_parse(&ip_pkt, uncomp_packet, comp->trace_callback,
	              comp->trace_callback_priv, ROHC_TRACE_COMP);

	// printf("\npkt-parse>>%d", getLDiffTime());

	/* find the best context for the packet */
	c = rohc_comp_find_ctxt(comp, &ip_pkt, -1, uncomp_packet.time);
	if(c == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to find a matching context or to create a new "
		             "context");
		goto error;
	}

	// printf("\nfind-context>>%d", getLDiffTime());

	/* create the ROHC packet: */
	rohc_packet->len = 0;

	/* use profile to compress packet */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "compress the packet #%d", comp->num_packets + 1);
	rohc_hdr_size =
		c->profile->encode(c, &ip_pkt, rohc_buf_data(*rohc_packet),
		                   rohc_buf_avail_len(*rohc_packet),
		                   &packet_type, &payload_offset);
	
	if(rohc_hdr_size < 0)
	{
		/* error while compressing, use the Uncompressed profile
		 * (except if we were already using the Uncompressed profile) */
		if(c->profile->id == ROHC_PROFILE_UNCOMPRESSED)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "error while compressing with uncompressed profile, "
			             "giving up");
			goto error_free_new_context;
		}
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "error while compressing with the profile, using "
		             "uncompressed profile");

		/* free context if it was just created */
		if(c->num_sent_packets <= 1)
		{
			c->profile->destroy(c);
			c->used = 0;
			assert(comp->num_contexts_used > 0);
			comp->num_contexts_used--;
		}

		/* find the best context for the Uncompressed profile */
		c = rohc_comp_find_ctxt(comp, &ip_pkt, ROHC_PROFILE_UNCOMPRESSED,
		                        uncomp_packet.time);
		if(c == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to find a matching Uncompressed context or to "
			             "create a new Uncompressed context");
			goto error;
		}

		/* use the Uncompressed profile to compress the packet */
		rohc_hdr_size =
			c->profile->encode(c, &ip_pkt, rohc_buf_data(*rohc_packet),
			                   rohc_buf_avail_len(*rohc_packet),
			                   &packet_type, &payload_offset);
		if(rohc_hdr_size < 0)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "error while compressing with uncompressed profile, "
			             "giving up");
			goto error_free_new_context;
		}
	}
	rohc_packet->len += rohc_hdr_size;

	// printf("\nencode-fail>>%d", getLDiffTime());

	/* the payload starts after the header, skip it */
	rohc_buf_pull(rohc_packet, rohc_hdr_size);
	payload_size = ip_pkt.len - payload_offset;

	/* copy full payload after ROHC header */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				"copy full %zd-byte payload", payload_size);
	rohc_buf_append(rohc_packet,
					rohc_buf_data_at(uncomp_packet, payload_offset),
					payload_size);

	/* unhide the ROHC header */
	rohc_buf_push(rohc_packet, rohc_hdr_size);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				"ROHC size = %zd bytes (header = %d, payload = %zu), output "
				"buffer size = %zu", rohc_packet->len, rohc_hdr_size,
				payload_size, rohc_buf_avail_len(*rohc_packet));

	// printf("\nwrap&map>>%d", getLDiffTime());

	/* report to user that compression was successful */
	status = ROHC_STATUS_OK;

	/* update some statistics:
	 *  - compressor statistics
	 *  - context statistics (global + last packet + last 16 packets) */
	comp->num_packets++;
	comp->total_uncompressed_size += uncomp_packet.len;
	comp->total_compressed_size += rohc_packet->len;
	comp->last_context = c;

	c->packet_type = packet_type;

	c->total_uncompressed_size += uncomp_packet.len;
	c->total_compressed_size += rohc_packet->len;
	c->header_uncompressed_size += payload_offset;
	c->header_compressed_size += rohc_hdr_size;
	c->num_sent_packets++;

	c->total_last_uncompressed_size = uncomp_packet.len;
	c->total_last_compressed_size = rohc_packet->len;
	c->header_last_uncompressed_size = payload_offset;
	c->header_last_compressed_size = rohc_hdr_size;

	//////////////////////////////////////////////////////////////////////////

	printf(", rohc_len:%lu, hdr_len:%d, rohc_data:", rohc_packet->len, rohc_hdr_size);
	for( size_t i=0 ; i<rohc_packet->len ; i++ )
	{
		printf("%hhu ", rohc_packet->data[i]);
	}
	printf("|\n");
	
	//////////////////////////////////////////////////////////////////////////

	// printf("\nstat>>%d\n", getLDiffTime());

	/* compression is successful */
	return status;

error_free_new_context:
	/* free context if it was just created */
	if(c->num_sent_packets <= 1)
	{
		c->profile->destroy(c);
		c->used = 0;
		assert(comp->num_contexts_used > 0);
		comp->num_contexts_used--;
	}
error:
	return ROHC_STATUS_ERROR;
}

/**
 * @brief Set the window width for the W-LSB encoding scheme
 *
 * Set the window width for the Window-based Least Significant Bits (W-LSB)
 * encoding. See section 4.5.2 of RFC 3095 for more details about the encoding
 * scheme.
 *
 * The width of the W-LSB window is set to 4 by default.
 *
 * @warning The value can not be modified after library initialization
 *
 * @param comp   The ROHC compressor
 * @param width  The width of the W-LSB sliding window
 * @return       true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_wlsb_window_width(struct rohc_comp *const comp,
                                     const size_t width)
{
	/* we need a valid compressor */
	if(comp == NULL)
	{
		return false;
	}

	/* the window width shall be in range ]0;ROHC_WLSB_WIDTH_MAX] */
	if(width == 0 || width > ROHC_WLSB_WIDTH_MAX)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "failed to "
		             "set width of W-LSB sliding window to %zd: window width "
		             "must be in range ]0;%u]", width, ROHC_WLSB_WIDTH_MAX);
		return false;
	}

	/* refuse to set a value if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "unable to "
		             "modify the W-LSB window width after initialization");
		return false;
	}

	comp->wlsb_window_width = width;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "width of W-LSB sliding window set to %zd", width);

	return true;
}


/**
 * @brief Set the timeouts in packets for IR and FO periodic refreshes
 *
 * Set the timeout values for IR and FO periodic refreshes. The IR timeout
 * shall be greater than the FO timeout. Both timeouts are expressed in
 * number of compressed packets.
 *
 * The IR timeout is set to \ref CHANGE_TO_IR_COUNT by default.
 * The FO timeout is set to \ref CHANGE_TO_FO_COUNT by default.
 *
 * @warning The values can not be modified after library initialization
 *
 * @param comp        The ROHC compressor
 * @param ir_timeout  The number of packets to compress before going back
 *                    to IR state to force a context refresh
 * @param fo_timeout  The number of packets to compress before going back
 *                    to FO state to force a context refresh
 * @return            true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_periodic_refreshes(struct rohc_comp *const comp,
                                      const size_t ir_timeout,
                                      const size_t fo_timeout)
{
	/* we need a valid compressor, positive non-zero timeouts,
	 * and IR timeout > FO timeout */
	if(comp == NULL)
	{
		return false;
	}
	if(ir_timeout == 0 || fo_timeout == 0 || ir_timeout <= fo_timeout)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "invalid "
		             "timeouts for context periodic refreshes (IR timeout = %zd, "
		             "FO timeout = %zd)", ir_timeout, fo_timeout);
		return false;
	}

	/* refuse to set values if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unable to modify the timeouts for periodic refreshes "
		             "after initialization");
		return false;
	}

	comp->periodic_refreshes_ir_timeout_pkts = ir_timeout;
	comp->periodic_refreshes_fo_timeout_pkts = fo_timeout;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "IR timeout for "
	          "context periodic refreshes set to %zd", ir_timeout);
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "FO timeout for "
	          "context periodic refreshes set to %zd", fo_timeout);

	return true;
}


/**
 * @brief Set the timeouts in ms for IR and FO periodic refreshes
 *
 * Set the timeout values for IR and FO periodic refreshes. The IR timeout
 * shall be greater than the FO timeout. Both timeouts are expressed in
 * milliseconds.
 *
 * The IR timeout is set to \ref CHANGE_TO_IR_TIME by default.
 * The FO timeout is set to \ref CHANGE_TO_FO_TIME by default.
 *
 * @warning The values can not be modified after library initialization
 *
 * @param comp        The ROHC compressor
 * @param ir_timeout  The delay (in ms) before going back to IR state
 *                    to force a context refresh
 * @param fo_timeout  The delay (in ms) before going back to FO state
 *                    to force a context refresh
 * @return            true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_periodic_refreshes_time(struct rohc_comp *const comp,
                                           const uint64_t ir_timeout,
                                           const uint64_t fo_timeout)
{
	/* we need a valid compressor, positive non-zero timeouts,
	 * and IR timeout > FO timeout */
	if(comp == NULL)
	{
		return false;
	}
	if(ir_timeout == 0 || fo_timeout == 0 || ir_timeout <= fo_timeout)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "invalid timeouts for context periodic refreshes "
		             "(IR timeout = %" PRIu64 " ms, FO timeout = %" PRIu64 " ms)",
		             ir_timeout, fo_timeout);
		return false;
	}

	/* refuse to set values if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unable to modify the timeouts for periodic refreshes "
		             "after initialization");
		return false;
	}

	comp->periodic_refreshes_ir_timeout_time = ir_timeout;
	comp->periodic_refreshes_fo_timeout_time = fo_timeout;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "IR timeout for "
	          "context periodic refreshes set to %" PRIu64 " ms", ir_timeout);
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "FO timeout for "
	          "context periodic refreshes set to %" PRIu64 " ms", fo_timeout);

	return true;
}

/**
 * @brief Is the given compression profile enabled for a compressor?
 *
 * Is the given compression profile enabled or disabled for a compressor?
 *
 * @param comp     The ROHC compressor
 * @param profile  The profile to ask status for
 * @return         Possible return values:
 *                  \li true if the profile exists and is enabled,
 *                  \li false if the compressor is not valid, the profile
 *                      does not exist, or the profile is disabled
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_profile_enabled(const struct rohc_comp *const comp,
                               const rohc_profile_t profile)
{
	size_t i;

	if(comp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(rohc_comp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == C_NUM_PROFILES)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC compression profile (ID = %d)", profile);
		goto error;
	}

	/* return profile status */
	return comp->enabled_profiles[i];

error:
	return false;
}

/**
 * @brief Enable a compression profile for a compressor
 *
 * Enable a compression profiles for a compressor.
 *
 * The ROHC compressor does not use the compression profiles that are not
 * enabled. Thus not enabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If the profile is already enabled, nothing is performed and success is
 * reported.
 *
 * @param comp     The ROHC compressor
 * @param profile  The profile to enable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c enable ROHC compression profile
 * \code
        ...
\endcode
 *
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_enable_profile(struct rohc_comp *const comp,
                              const rohc_profile_t profile)
{
	size_t i;

	if(comp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(rohc_comp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == C_NUM_PROFILES)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC compression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as enabled */
	comp->enabled_profiles[i] = true;
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "ROHC compression profile (ID = %d) enabled", profile);

	return true;

error:
	return false;
}

/**
 * @brief Disable a compression profile for a compressor
 *
 * Disable a compression profile for a compressor.
 *
 * The ROHC compressor does not use the compression profiles that were
 * disabled. Thus disabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If the profile is already disabled, nothing is performed and success is
 * reported.
 *
 * @param comp     The ROHC compressor
 * @param profile  The profile to disable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_disable_profile(struct rohc_comp *const comp,
                               const rohc_profile_t profile)
{
	size_t i;

	if(comp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(rohc_comp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == C_NUM_PROFILES)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC compression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as disabled */
	comp->enabled_profiles[i] = false;
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "ROHC compression profile (ID = %d) disabled", profile);

	return true;

error:
	return false;
}


/**
 * @brief Enable several compression profiles for a compressor
 *
 * Enable several compression profiles for a compressor. The list of profiles
 * to enable shall stop with -1.
 *
 * The ROHC compressor does not use the compression profiles that are not
 * enabled. Thus not enabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already enabled, nothing is performed
 * and success is reported.
 *
 * @param comp  The ROHC compressor
 * @param ...   The sequence of compression profiles to enable, the sequence
 *              shall be terminated by -1
 * @return      true if all of the profiles exist,
 *              false if at least one of the profiles does not exist
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c enable ROHC compression profiles
 * \code
        ...
\endcode
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_disable_profile
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_enable_profiles(struct rohc_comp *const comp,
                               ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(comp == NULL)
	{
		goto error;
	}

	va_start(profiles, comp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_comp_enable_profile(comp, profile_id);
		if(!is_ok)
		{
			err_nr++;
		}
	}

	va_end(profiles);

	return (err_nr == 0);

error:
	return false;
}


/**
 * @brief Disable several compression profiles for a compressor
 *
 * Disable several compression profiles for a compressor. The list of profiles
 * to disable shall stop with -1.
 *
 * The ROHC compressor does not use the compression profiles that were
 * disabled. Thus disabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already disabled, nothing is performed
 * and success is reported.
 *
 * @param comp  The ROHC compressor
 * @param ...   The sequence of compression profiles to disable, the sequence
 *              shall be terminated by -1
 * @return      true if all of the profiles exist,
 *              false if at least one of the profiles does not exist
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profile
 */
bool rohc_comp_disable_profiles(struct rohc_comp *const comp,
                                ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(comp == NULL)
	{
		goto error;
	}

	va_start(profiles, comp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_comp_disable_profile(comp, profile_id);
		if(!is_ok)
		{
			err_nr++;
		}
	}

	va_end(profiles);

	return (err_nr == 0);

error:
	return false;
}

/**
 * @brief Get the maximal CID value the compressor uses
 *
 * Get the maximal CID value the compressor uses, ie. the \e MAX_CID parameter
 * defined in RFC 3095.
 *
 * @param comp          The ROHC compressor
 * @param[out] max_cid  The current maximal CID value
 * @return              true if MAX_CID was successfully retrieved,
 *                      false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_get_max_cid(const struct rohc_comp *const comp,
                           size_t *const max_cid)
{
	if(comp == NULL || max_cid == NULL)
	{
		goto error;
	}

	*max_cid = comp->medium.max_cid;
	return true;

error:
	return false;
}


/**
 * @brief Get the CID type that the compressor uses
 *
 * Get the CID type that the compressor currently uses.
 *
 * @param comp           The ROHC compressor
 * @param[out] cid_type  The current CID type among \ref ROHC_SMALL_CID and
 *                       \ref ROHC_LARGE_CID
 * @return               true if the CID type was successfully retrieved,
 *                       false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_get_cid_type(const struct rohc_comp *const comp,
                            rohc_cid_type_t *const cid_type)
{
	if(comp == NULL || cid_type == NULL)
	{
		goto error;
	}

	*cid_type = comp->medium.cid_type;
	return true;

error:
	return false;
}


/**
 * @brief Enable/disable features for ROHC compressor
 *
 * Enable/disable features for ROHC compressor. Features control whether
 * mechanisms defined as optional by RFCs are enabled or not.
 *
 * Available features are listed by \ref rohc_comp_features_t. They may be
 * combined by XOR'ing them together.
 *
 * @warning Changing the feature set while library is used is not supported
 *
 * @param comp      The ROHC compressor
 * @param features  The feature set to enable/disable
 * @return          true if the feature set was successfully enabled/disabled,
 *                  false if a problem occurred
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_features_t
 */
bool rohc_comp_set_features(struct rohc_comp *const comp,
                            const rohc_comp_features_t features)
{
	const rohc_comp_features_t all_features =
		ROHC_COMP_FEATURE_NO_IP_CHECKSUMS |
		ROHC_COMP_FEATURE_DUMP_PACKETS |
		ROHC_COMP_FEATURE_TIME_BASED_REFRESHES;

	/* compressor must be valid */
	if(comp == NULL)
	{
		/* cannot print a trace without a valid compressor */
		goto error;
	}

	/* reject unsupported features */
	if((features & all_features) != features)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "feature set 0x%x is not supported (supported features "
		             "set is 0x%x)", features, all_features);
		goto error;
	}

	/* record new feature set */
	comp->features = features;

	return true;

error:
	return false;
}

/**
 * @brief Get some information about the last compressed packet
 *
 * Get some information about the last compressed packet.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_comp_last_packet_info2_t structure with the \e version_major and
 * \e version_minor fields set to one of the following supported versions:
 *  - Major 0, minor 0
 *
 * See the \ref rohc_comp_last_packet_info2_t structure for details about
 * fields that are supported in the above versions.
 *
 * @param comp          The ROHC compressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_last_packet_info2_t
 */
bool rohc_comp_get_last_packet_info2(const struct rohc_comp *const comp,
                                     rohc_comp_last_packet_info2_t *const info)
{
	if(comp == NULL)
	{
		goto error;
	}

	if(comp->last_context == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "last context found in compressor is not valid");
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "structure for last packet information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->context_id = comp->last_context->cid;
		info->is_context_init = (comp->last_context->num_sent_packets == 1);
		info->context_mode = comp->last_context->mode;
		info->context_state = comp->last_context->state;
		info->context_used = (comp->last_context->used ? true : false);
		info->profile_id = comp->last_context->profile->id;
		info->packet_type = comp->last_context->packet_type;
		info->total_last_uncomp_size = comp->last_context->total_last_uncompressed_size;
		info->header_last_uncomp_size = comp->last_context->header_last_uncompressed_size;
		info->total_last_comp_size = comp->last_context->total_last_compressed_size;
		info->header_last_comp_size = comp->last_context->header_last_compressed_size;

		/* new fields added by minor versions */
		if(info->version_minor > 0)
		{
			rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported minor version (%u) of the structure for "
			           "last packet information", info->version_minor);
			goto error;
		}
	}
	else
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for last "
		           "packet information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get some general information about the compressor
 *
 * Get some general information about the compressor.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_comp_general_info_t structure with the \e version_major and
 * \e version_minor fields set to one of the following supported versions:
 *  - Major 0, minor 0
 *
 * See the \ref rohc_comp_general_info_t structure for details about fields
 * that are supported in the above versions.
 *
 * @param comp          The ROHC compressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_general_info_t
 */
bool rohc_comp_get_general_info(const struct rohc_comp *const comp,
                                rohc_comp_general_info_t *const info)
{
	if(comp == NULL)
	{
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "structure for general information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->contexts_nr = comp->num_contexts_used;
		info->packets_nr = comp->num_packets;
		info->uncomp_bytes_nr = comp->total_uncompressed_size;
		info->comp_bytes_nr = comp->total_compressed_size;

		/* new fields added by minor versions */
		if(info->version_minor > 0)
		{
			rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported minor version (%u) of the structure for "
			           "general information", info->version_minor);
			goto error;
		}
	}
	else
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for "
		           "general information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Give a description for the given ROHC compression context state
 *
 * Give a description for the given ROHC compression context state.
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of compression context states
 * used by the library. If unsure, ask on the mailing list.
 *
 * @param state  The compression context state to get a description for
 * @return       A string that describes the given compression context state
 *
 * @ingroup rohc_comp
 */
const char * rohc_comp_get_state_descr(const rohc_comp_state_t state)
{
	switch(state)
	{
		case ROHC_COMP_STATE_IR:
			return "IR";
		case ROHC_COMP_STATE_FO:
			return "FO";
		case ROHC_COMP_STATE_SO:
			return "SO";
		case ROHC_COMP_STATE_UNKNOWN:
		default:
			return "no description";
	}
}


/*
 * Definitions of private functions
 */

/**
 * @brief Find out a ROHC profile given a profile ID
 *
 * @param comp       The ROHC compressor
 * @param profile_id The ID of the ROHC profile to find out
 * @return           The ROHC profile if found, NULL otherwise
 */
static const struct rohc_comp_profile *
	rohc_get_profile_from_id(const struct rohc_comp *comp,
	                         const rohc_profile_t profile_id)
{
	size_t i;

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		/* if the profile IDs match and the profile is enabled */
		if(rohc_comp_profiles[i]->id == profile_id && comp->enabled_profiles[i])
		{
			return rohc_comp_profiles[i];
		}
	}

	return NULL;
}


/**
 * @brief Find out a ROHC profile given an IP protocol ID
 *
 * @param comp    The ROHC compressor
 * @param packet  The packet to find a compression profile for
 * @return        The ROHC profile if found, NULL otherwise
 */
static const struct rohc_comp_profile *
	c_get_profile_from_packet(const struct rohc_comp *const comp,
	                          const struct net_pkt *const packet)
{
	size_t i;

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "try to find the best profile for packet with transport "
	           "protocol %u", packet->transport->proto);

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		bool check_profile;

		/* skip profile if the profile is not enabled */
		if(!comp->enabled_profiles[i])
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "skip disabled profile '%s' (0x%04x)",
			           rohc_get_profile_descr(rohc_comp_profiles[i]->id),
			           rohc_comp_profiles[i]->id);
			continue;
		}

		/* does the profile accept the packet? */
		check_profile = rohc_comp_profiles[i]->check_profile(comp, packet);
		if(!check_profile)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "skip profile '%s' (0x%04x) because it does not match "
			           "packet",rohc_get_profile_descr(rohc_comp_profiles[i]->id),
			           rohc_comp_profiles[i]->id);
			continue;
		}

		/* the packet is compatible with the profile, let's go with it! */
		return rohc_comp_profiles[i];
	}

	return NULL;
}


/**
 * @brief Create a compression context
 *
 * @param comp          The ROHC compressor
 * @param profile       The profile to associate the context with
 * @param packet        The packet to create a compression context for
 * @param arrival_time  The time at which packet was received (0 if unknown,
 *                      or to disable time-related features in ROHC protocol)
 * @param do_ctxt_replication  Are we able to replicate an existing context?
 * @param cid_for_replication  The context to replicate if any
 * @return              The compression context if successful, NULL otherwise
 */
static struct rohc_comp_ctxt *
	c_create_context(struct rohc_comp *const comp,
	                 const struct rohc_comp_profile *const profile,
	                 const struct net_pkt *const packet,
	                 const struct rohc_ts arrival_time,
	                 const bool do_ctxt_replication,
	                 const rohc_cid_t cid_for_replication)
{
	struct rohc_comp_ctxt *c;
	rohc_cid_t cid_to_use;

	assert(comp != NULL);
	assert(profile != NULL);
	assert(packet != NULL);

	cid_to_use = cid_for_replication;

	assert(do_ctxt_replication==false);
	/* if all the contexts in the array are used:
	 *   => recycle the oldest context to make room
	 * if at least one context in the array is not used:
	 *   => pick the first unused context
	 */
	cid_to_use = 0;
	if(comp->num_contexts_used > comp->medium.max_cid)
	{
		/* all the contexts in the array were used, recycle the oldest context
		 * to make some room */

		uint64_t oldest;
		rohc_cid_t i;

		/* find the oldest context */
		oldest = 0xffffffff;
		for(i = 0; i <= comp->medium.max_cid; i++)
		{
			if(comp->contexts[i].latest_used < oldest)
			{
				oldest = comp->contexts[i].latest_used;
				cid_to_use = i;
			}
		}

		/* destroy the oldest context before replacing it with a new one */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "recycle oldest context (CID = %zu)", cid_to_use);
		comp->contexts[cid_to_use].profile->destroy(&comp->contexts[cid_to_use]);
		comp->contexts[cid_to_use].used = 0;
		assert(comp->num_contexts_used > 0);
		comp->num_contexts_used--;
	}
	else
	{
		/* there was at least one unused context in the array, pick the first
		 * unused context in the context array */

		rohc_cid_t i;

		/* find the first unused context */
		for(i = 0; i <= comp->medium.max_cid; i++)
		{
			if(comp->contexts[i].used == 0)
			{
				cid_to_use = i;
				break;
			}
		}

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "take the first unused context (CID = %zu)", cid_to_use);
	}

	/* initialize the previously found context */
	c = &comp->contexts[cid_to_use];

	c->ir_count = 0;
	c->fo_count = 0;
	c->so_count = 0;
	c->go_back_fo_count = 0;
	c->go_back_fo_time = arrival_time;
	c->go_back_ir_count = 0;
	c->go_back_ir_time = arrival_time;

	c->total_uncompressed_size = 0;
	c->total_compressed_size = 0;
	c->header_uncompressed_size = 0;
	c->header_compressed_size = 0;

	c->total_last_uncompressed_size = 0;
	c->total_last_compressed_size = 0;
	c->header_last_uncompressed_size = 0;
	c->header_last_compressed_size = 0;

	c->num_sent_packets = 0;

	c->cid = cid_to_use;
	c->profile = profile;

	c->mode = ROHC_U_MODE;
	c->state = ROHC_COMP_STATE_IR;

	c->compressor = comp;

	if(!profile->create(c, packet))
	{
		return NULL;
	}

	/* if creation is successful, mark the context as used */
	c->used = 1;
	c->first_used = arrival_time.sec;
	c->latest_used = arrival_time.sec;
	assert(comp->num_contexts_used <= comp->medium.max_cid);
	comp->num_contexts_used++;

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "context (CID = %zu) created at %" PRIu64 " seconds (num_used = %zu)",
	           c->cid, c->latest_used, comp->num_contexts_used);
	return c;
}


/**
 * @brief Find a compression context given an IP packet
 *
 * @param comp             The ROHC compressor
 * @param packet           The packet to find a compression context for
 * @param profile_id_hint  If positive, indicate the profile to use
 * @param arrival_time     The time at which packet was received
 *                         (0 if unknown, or to disable time-related features
 *                          in the ROHC protocol)
 * @return                 The context if found or successfully created,
 *                         NULL if not found
 */
static struct rohc_comp_ctxt *
	rohc_comp_find_ctxt(struct rohc_comp *const comp,
	                    const struct net_pkt *const packet,
	                    const int profile_id_hint,
	                    const struct rohc_ts arrival_time)
{
	const struct rohc_comp_profile *profile;
	struct rohc_comp_ctxt *context;
	size_t num_used_ctxt_seen = 0;
	rohc_cid_t i;

	/* use the suggested profile if any, otherwise find the best profile for
	 * the packet */
	if(profile_id_hint < 0)
	{
		profile = c_get_profile_from_packet(comp, packet);
	}
	else
	{
		profile = rohc_get_profile_from_id(comp, profile_id_hint);
	}
	if(profile == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "no profile found for packet, giving up");
		goto not_found;
	}
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "using profile '%s' (0x%04x)",
	           rohc_get_profile_descr(profile->id), profile->id);

	/* get the context using help from the profile we just found */
	for(i = 0; i <= comp->medium.max_cid; i++)
	{
		size_t cr_score = 0;
		context = &comp->contexts[i];

		/* don't even look at unused contexts */
		if(!context->used)
		{
			continue;
		}
		num_used_ctxt_seen++;

		/* don't look at contexts with the wrong profile */
		if(context->profile->id != profile->id)
		{
			continue;
		}

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "check context CID = %zu with same profile", context->cid);

		/* ask the profile whether the packet matches the context */
		if(context->profile->check_context(context, packet, &cr_score))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
						"re-using context CID = %zu", context->cid);
			break;
		}
		rohc_comp_debug(context, "context CID %zu scores %zu for Context Replication",
		                context->cid, cr_score);

		/* if all used contexts were checked, no need go search further */
		if(num_used_ctxt_seen >= comp->num_contexts_used)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "no context was found");
			context = NULL;
			break;
		}
	}
	if(context == NULL || i > comp->medium.max_cid)
	{
		/* context not found, create a new one */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no existing context found for packet, create a new one");
		context = c_create_context(comp, profile, packet, arrival_time,
		                           false, 0);
		if(context == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to create a new context");
			goto not_found;
		}
	}
	else
	{
		/* matching context found, update use timestamp */
		context->latest_used = arrival_time.sec;
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "context (CID = %zu) used at %" PRIu64 " seconds",
		           context->cid, context->latest_used);
	}

	return context;

not_found:
	return NULL;
}

/**
 * @brief Create the array of compression contexts
 *
 * @param comp The ROHC compressor
 * @return     true if the creation is successful, false otherwise
 */
static bool c_create_contexts(struct rohc_comp *const comp)
{
	assert(comp->contexts == NULL);

	comp->num_contexts_used = 0;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "create enough room for %zu contexts (MAX_CID = %zu)",
	          comp->medium.max_cid + 1, comp->medium.max_cid);

	comp->contexts = calloc(comp->medium.max_cid + 1,
	                        sizeof(struct rohc_comp_ctxt));
	if(comp->contexts == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "cannot allocate memory for contexts");
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Destroy all the compression contexts in the context array
 *
 * The profile-specific contexts are also destroyed.
 *
 * @param comp The ROHC compressor
 */
static void c_destroy_contexts(struct rohc_comp *const comp)
{
	rohc_cid_t i;

	assert(comp->contexts != NULL);

	for(i = 0; i <= comp->medium.max_cid; i++)
	{
		if(comp->contexts[i].used && comp->contexts[i].profile != NULL)
		{
			comp->contexts[i].profile->destroy(&comp->contexts[i]);
		}

		if(comp->contexts[i].used)
		{
			comp->contexts[i].used = 0;
			assert(comp->num_contexts_used > 0);
			comp->num_contexts_used--;
		}
	}
	assert(comp->num_contexts_used == 0);

	free(comp->contexts);
	comp->contexts = NULL;
}


/**
 * @brief Change the mode of the context.
 *
 * @param context  The compression context
 * @param new_mode The new mode the context must enter in
 */
void rohc_comp_change_mode(struct rohc_comp_ctxt *const context,
                           const rohc_mode_t new_mode)
{
	if(context->mode != new_mode)
	{
		/* TODO: downward transition to U-mode is not yet supported */
		if(new_mode == ROHC_U_MODE)
		{
			rohc_comp_warn(context, "ignore change to U-mode because such a "
			               "transition is not supported yet");
			return;
		}

		/* change mode and go back to IR state */
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %zu: change from mode %d to mode %d",
		          context->cid, context->mode, new_mode);
		context->mode = new_mode;
	}
}


/**
 * @brief Change the state of the context.
 *
 * @param context   The compression context
 * @param new_state The new state the context must enter in
 */
void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const rohc_comp_state_t new_state)
{
	if(new_state != context->state)
	{
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %zu: change from state %d to state %d",
		          context->cid, context->state, new_state);

		/* reset counters */
		context->ir_count = 0;
		context->fo_count = 0;
		context->so_count = 0;

		/* change state */
		context->state = new_state;
	}
}


/**
 * @brief Periodically change the context state after a certain number
 *        of packets.
 *
 * @param context   The compression context
 * @param pkt_time  The time of packet arrival
 */
void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context,
                                        const struct rohc_ts pkt_time)
{
	rohc_comp_state_t next_state;

	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "CID %zu: timeouts for periodic refreshes: FO = %zu / %zu, "
	           "IR = %zu / %zu", context->cid, context->go_back_fo_count,
	           context->compressor->periodic_refreshes_fo_timeout_pkts,
	           context->go_back_ir_count,
	           context->compressor->periodic_refreshes_ir_timeout_pkts);

	if(context->go_back_ir_count >=
	   context->compressor->periodic_refreshes_ir_timeout_pkts)
	{
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %zu: periodic change to IR state", context->cid);
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if((context->compressor->features & ROHC_COMP_FEATURE_TIME_BASED_REFRESHES) != 0 &&
	        rohc_time_interval(context->go_back_ir_time, pkt_time) >=
	        context->compressor->periodic_refreshes_ir_timeout_time * 1000U)
	{
		const uint64_t interval_since_ir_refresh =
			rohc_time_interval(context->go_back_ir_time, pkt_time);
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %zu: force IR refresh since %" PRIu64 " us elapsed since "
		          "last IR packet", context->cid, interval_since_ir_refresh);
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if(context->go_back_fo_count >=
	        context->compressor->periodic_refreshes_fo_timeout_pkts)
	{
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %zu: periodic change to FO state", context->cid);
		context->go_back_fo_count = 0;
		next_state = ROHC_COMP_STATE_FO;
	}
	else if((context->compressor->features & ROHC_COMP_FEATURE_TIME_BASED_REFRESHES) != 0 &&
	        rohc_time_interval(context->go_back_fo_time, pkt_time) >=
	        context->compressor->periodic_refreshes_fo_timeout_time * 1000U)
	{
		const uint64_t interval_since_fo_refresh =
			rohc_time_interval(context->go_back_fo_time, pkt_time);
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %zu: force FO refresh since %" PRIu64 " us elapsed since "
		          "last FO packet", context->cid, interval_since_fo_refresh);
		context->go_back_fo_count = 0;
		next_state = ROHC_COMP_STATE_FO;
	}
	else
	{
		next_state = context->state;
	}

	rohc_comp_change_state(context, next_state);

	if(context->state == ROHC_COMP_STATE_SO)
	{
		context->go_back_ir_count++;
		context->go_back_fo_count++;
	}
	else if(context->state == ROHC_COMP_STATE_FO)
	{
		context->go_back_ir_count++;
		context->go_back_fo_time = pkt_time;
	}
	else /* ROHC_COMP_STATE_IR */
	{
		context->go_back_fo_time = pkt_time;
		context->go_back_ir_time = pkt_time;
	}
}
