/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2008,2009,2010,2012,2013,2014 Viveris Technologies
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
 * @file   rohc_decomp_rfc3095.c
 * @brief  Generic framework for RFC3095-based decompression profiles such as
 *         IP-only, UDP, UDP-Lite, ESP, and RTP profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

#include "rohc_decomp_rfc3095.h"
#include "rohc_traces_internal.h"
#include "rohc_time_internal.h"
#include "rohc_debug.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "rohc_bit_ops.h"
#include "rohc_decomp_internals.h"
#include "rohc_decomp_detect_packet.h"
#include "decomp_wlsb.h"
#include "crc.h"

#include "config.h" /* for WORDS_BIGENDIAN definition */

#include <string.h>
#include <assert.h>


/*
 * Private function prototypes for parsing the static and dynamic parts
 * of the IR and IR-DYN headers
 */

static int parse_static_part_ip(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const packet,
                                const size_t length,
                                struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int parse_static_part_ipv4(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *packet,
                                  const size_t length,
                                  struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int parse_dynamic_part_ip(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const packet,
                                 const size_t length,
                                 struct rohc_extr_ip_bits *const bits,
                                 struct list_decomp *const list_decomp)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));
static int parse_dynamic_part_ipv4(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *packet,
                                   const size_t length,
                                   struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

/*
 * Private function prototypes for parsing the different UO* headers
 */

static bool parse_ir(const struct rohc_decomp_ctxt *const context,
                     const uint8_t *const rohc_packet,
                     const size_t rohc_length,
                     const size_t large_cid_len,
                     rohc_packet_t *const packet_type,
                     struct rohc_decomp_crc *const extr_crc,
                     struct rohc_extr_bits *const bits,
                     size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 7, 8)));

static bool parse_irdyn(const struct rohc_decomp_ctxt *const context,
                        const uint8_t *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_decomp_crc *const extr_crc,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 7, 8)));

static bool parse_uo0(const struct rohc_decomp_ctxt *const context,
                      const uint8_t *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_decomp_crc *const extr_crc,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 7, 8)));

static bool parse_uo1(const struct rohc_decomp_ctxt *const context,
                      const uint8_t *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_decomp_crc *const extr_crc,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 7, 8)));
static bool parse_uor2(const struct rohc_decomp_ctxt *const context,
                       const uint8_t *const rohc_packet,
                       const size_t rohc_length,
                       const size_t large_cid_len,
                       rohc_packet_t *const packet_type,
                       struct rohc_decomp_crc *const extr_crc,
                       struct rohc_extr_bits *const bits,
                       size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 7, 8)));
static bool parse_uo_remainder(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_extr_bits *const bits,
                               size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

/*
 * Private function prototypes for building the uncompressed headers
 */

static bool build_uncomp_ip(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_decoded_ip_values decoded,
                            uint8_t *const dest,
                            const size_t uncomp_hdrs_max_len,
                            size_t *const uncomp_hdrs_len,
                            const size_t payload_size,
                            const struct list_decomp *const list_decomp)
	__attribute__((warn_unused_result, nonnull(1, 3, 5)));
static bool build_uncomp_ipv4(const struct rohc_decomp_ctxt *const context,
                              const struct rohc_decoded_ip_values decoded,
                              uint8_t *const dest,
                              const size_t uncomp_hdrs_max_len,
                              size_t *const uncomp_hdrs_len,
                              const size_t payload_size)
	__attribute__((warn_unused_result, nonnull(1, 3, 5)));


/*
 * Private function prototypes for decoding the extracted bits
 */

static bool decode_ip_values_from_bits(const struct rohc_decomp_ctxt *const context,
                                       const struct rohc_decomp_rfc3095_changes *const ctxt,
                                       const struct ip_id_offset_decode *const ip_id_decode,
                                       const uint32_t decoded_sn,
                                       const rohc_lsb_ref_t lsb_ref_type,
                                       const struct rohc_extr_ip_bits *const bits,
                                       const char *const descr,
                                       const size_t ip_hdr_pos,
                                       struct rohc_decoded_ip_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 9)));


/*
 * Private function prototypes for miscellaneous functions
 */

static bool check_uncomp_crc(const struct rohc_decomp *const decomp,
                             const struct rohc_decomp_ctxt *const context,
                             const uint8_t *const outer_ip_hdr,
                             const uint8_t *const inner_ip_hdr,
                             const uint8_t *const next_header,
                             const rohc_crc_type_t crc_type,
                             const uint8_t crc_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static bool is_sn_wraparound(const struct rohc_ts cur_arrival_time,
                             const struct rohc_ts arrival_times[ROHC_MAX_ARRIVAL_TIMES],
                             const size_t arrival_times_nr,
                             const size_t arrival_times_index,
                             const size_t k,
                             const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, pure));

static void reset_extr_bits(const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                            struct rohc_extr_bits *const bits)
	__attribute__((nonnull(1, 2)));



/*
 * Definitions of public functions
 */

/**
 * @brief Create the RFC3095 volatile and persistent parts of the context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context            The decompression context
 * @param[out] persist_ctxt  The persistent part of the decompression context
 * @param[out] volat_ctxt    The volatile part of the decompression context
 * @param trace_cb           The function to call for printing traces
 * @param trace_cb_priv      An optional private context, may be NULL
 * @param profile_id         The ID of the associated decompression profile
 * @return                   true if the Uncompressed context was successfully
 *                           created, false if a problem occurred
 */
bool rohc_decomp_rfc3095_create(const struct rohc_decomp_ctxt *const context,
                                struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                                struct rohc_decomp_volat_ctxt *const volat_ctxt,
                                rohc_trace_callback2_t trace_cb,
                                void *const trace_cb_priv,
                                const int profile_id)
{
	assert(profile_id>=0);
	assert(trace_cb_priv==NULL || trace_cb_priv!=NULL);
	assert(trace_cb==NULL || trace_cb!=NULL);
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;

	/* allocate memory for the generic context */
	*persist_ctxt = calloc(1, sizeof(struct rohc_decomp_rfc3095_ctxt));
	if((*persist_ctxt) == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "no memory for the generic decompression context");
		goto quit;
	}
	rfc3095_ctxt = *persist_ctxt;

	/* create the Offset IP-ID decoding context for outer IP header */
	ip_id_offset_init(&rfc3095_ctxt->outer_ip_id_offset_ctxt);

	rfc3095_ctxt->outer_ip_changes = calloc(2, sizeof(struct rohc_decomp_rfc3095_changes));
	if(rfc3095_ctxt->outer_ip_changes == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the outer IP header changes");
		goto free_context;
	}

	/* no default next header */
	rfc3095_ctxt->next_header_proto = 0;

	/* default CRC computation */
	rfc3095_ctxt->compute_crc_static = compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = compute_crc_dynamic;
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	/* volatile part of the decompression context */
	volat_ctxt->crc.type = ROHC_CRC_TYPE_NONE;
	volat_ctxt->crc.bits_nr = 0;
	volat_ctxt->extr_bits = malloc(sizeof(struct rohc_extr_bits));
	if(volat_ctxt->extr_bits == NULL)
	{
		rohc_decomp_warn(context, "failed to allocate memory for the volatile part "
		                 "of one of the RFC3095 decompression context");
		goto free_outer_ip_changes;
	}
	volat_ctxt->decoded_values = malloc(sizeof(struct rohc_decoded_values));
	if(volat_ctxt->decoded_values == NULL)
	{
		rohc_decomp_warn(context, "failed to allocate memory for the volatile part "
		                 "of one of the RFC3095 decompression context");
		goto free_extr_bits;
	}

	return true;

free_extr_bits:
	zfree(volat_ctxt->extr_bits);
free_outer_ip_changes:
	zfree(rfc3095_ctxt->outer_ip_changes);
free_context:
	zfree(rfc3095_ctxt);
quit:
	return false;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param rfc3095_ctxt  The generic decompression context
 * @param volat_ctxt    The volatile part of the decompression context
 */
void rohc_decomp_rfc3095_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                                 const struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	/* free the volatile part of the decompression context */
	free(volat_ctxt->decoded_values);
	free(volat_ctxt->extr_bits);

	/* destroy the information about the IP headers */
	zfree(rfc3095_ctxt->outer_ip_changes);

	/* destroy profile-specific part */
	zfree(rfc3095_ctxt->specific);

	/* destroy generic context itself */
	free(rfc3095_ctxt);
}


/**
 * @brief Parse one IR, IR-DYN, UO-0, UO-1*, or UOR-2* packet
 *
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param large_cid_len        The length of the optional large CID field
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc        The CRC bits extracted from the ROHC header
 * @param[out] bits            The bits extracted from the ROHC header
 * @param[out] rohc_hdr_len    The length of the ROHC header (in bytes)
 * @return                     true if packet is successfully parsed,
 *                             false otherwise
 *
 * @see parse_ir
 * @see parse_irdyn
 * @see parse_uo0
 * @see parse_uo1
 * @see parse_uo1rtp
 * @see parse_uo1id
 * @see parse_uo1ts
 * @see parse_uor2
 * @see parse_uor2rtp
 * @see parse_uor2id
 * @see parse_uor2ts
 */
bool rfc3095_decomp_parse_pkt(const struct rohc_decomp_ctxt *const context,
                              const struct rohc_buf rohc_packet,
                              const size_t large_cid_len,
                              rohc_packet_t *const packet_type,
                              struct rohc_decomp_crc *const extr_crc,
                              struct rohc_extr_bits *const bits,
                              size_t *const rohc_hdr_len)
{
	const uint8_t *const rohc_packet_data = rohc_buf_data(rohc_packet);
	const size_t rohc_length = rohc_packet.len;

	bool (*parse)(const struct rohc_decomp_ctxt *const _context,
	              const uint8_t *const _rohc_packet,
	              const size_t _rohc_length,
	              const size_t _large_cid_len,
	              rohc_packet_t *const _packet_type,
	              struct rohc_decomp_crc *const _extr_crc,
	              struct rohc_extr_bits *const _bits,
	              size_t *const _rohc_hdr_len)
		__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 7, 8)));

	assert(context != NULL);
	assert(packet_type != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	/* what function to call for parsing the packet? */
	switch(*packet_type)
	{
		case ROHC_PACKET_IR:
		{
			parse = parse_ir;
			break;
		}
		case ROHC_PACKET_IR_DYN:
		{
			parse = parse_irdyn;
			break;
		}
		case ROHC_PACKET_UO_0:
		{
			parse = parse_uo0;
			break;
		}
		case ROHC_PACKET_UO_1:
		{
			parse = parse_uo1;
			break;
		}
		case ROHC_PACKET_UOR_2:
		{
			parse = parse_uor2;
			break;
		}
		default:
		{
			rohc_decomp_warn(context, "unknown packet type (%d)", *packet_type);
			goto error;
		}
	}

	/* let's parse the packet! */
	return parse(context, rohc_packet_data, rohc_length, large_cid_len, packet_type,
	             extr_crc, bits, rohc_hdr_len);

error:
	return false;
}


/**
 * @brief Parse one IR packet
 *
 * \verbatim

 IR packet (5.7.7.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
 7  |         Dynamic chain         |  present if D = 1, variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 8  |             SN                |  2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    |                               |
    |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc  The CRC extracted from the ROHC packet
 * @param bits           OUT: The bits extracted from the IR header
 * @param rohc_hdr_len   OUT: The size of the IR header
 * @return               true if IR is successfully parsed, false otherwise
 */
static bool parse_ir(const struct rohc_decomp_ctxt *const context,
                     const uint8_t *const rohc_packet,
                     const size_t rohc_length,
                     const size_t large_cid_len,
                     rohc_packet_t *const packet_type,
                     struct rohc_decomp_crc *const extr_crc,
                     struct rohc_extr_bits *const bits,
                     size_t *const rohc_hdr_len)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt = context->persist_ctxt;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const uint8_t *rohc_remain_data;
	size_t rohc_remain_len;

	/* helper variables for values returned by functions */
	uint8_t packet_type_x_field;
	bool dynamic_present;
	int size;

	assert(rfc3095_ctxt != NULL);
	assert(rohc_packet != NULL);
	assert(packet_type != NULL);
	assert((*packet_type) == ROHC_PACKET_IR);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(rfc3095_ctxt, bits);
	extr_crc->type = ROHC_CRC_TYPE_NONE;

	/* packet must large enough for:
	 * IR type + (large CID + ) Profile ID + CRC */
	if(rohc_remain_len < (1 + large_cid_len + 2))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* is the dynamic flag set ? */
	packet_type_x_field = GET_BIT_0(rohc_remain_data);
	
	/* dynamic chain is not optional for other profiles */
	dynamic_present = true;

	/* the x bit of the packet type byte is reserved and shall be 0 */
	if(packet_type_x_field != 0)
	{
		rohc_decomp_warn(context, "sender does not conform to ROHC standards: "
							"the reserved bit in the packet type byte of the IR "
							"packet shall be set to 0, but it is not");
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}
	rohc_decomp_debug(context, "dynamic chain is%s present after static chain",
	                  dynamic_present ? "" : " not");

	/* skip the IR type, optional large CID bytes, and Profile ID */
	rohc_remain_data += large_cid_len + 2;
	rohc_remain_len -= large_cid_len + 2;
	*rohc_hdr_len += large_cid_len + 2;

	/* parse CRC */
	extr_crc->bits = GET_BIT_0_7(rohc_remain_data);
	extr_crc->bits_nr = 8;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x",
	                  extr_crc->bits_nr, extr_crc->bits);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* decode the static part of the outer header */
	size = parse_static_part_ip(context, rohc_remain_data, rohc_remain_len,
	                            &bits->outer_ip);
	if(size == -1)
	{
		rohc_decomp_warn(context, "cannot parse the outer IP static part");
		goto error;
	}
	rohc_remain_data += size;
	rohc_remain_len -= size;
	*rohc_hdr_len += size;

	/* check for IP version switch during context re-use */
	if(context->num_recv_packets >= 1 &&
	   bits->outer_ip.version != ip_get_version(&rfc3095_ctxt->outer_ip_changes->ip))
	{
		rohc_decomp_debug(context, "outer IP version mismatch (packet = %d, "
		                  "context = %d) -> context is being reused",
		                  bits->outer_ip.version,
		                  ip_get_version(&rfc3095_ctxt->outer_ip_changes->ip));
		bits->is_context_reused = true;
	}

	/* check for the presence of a second IP header */
	assert(bits->outer_ip.proto_nr == 8);
	/* check for 2 to 1 IP headers switch during context re-use */
	if(context->num_recv_packets >= 1 && rfc3095_ctxt->multiple_ip)
	{
		rohc_decomp_debug(context, "number of IP headers mismatch (packet "
							"= 1, context = 2) -> context is being reused");
		bits->is_context_reused = true;
	}

	bits->multiple_ip = false;

	/* parse the static part of the next header header if necessary */
	if(rfc3095_ctxt->parse_static_next_hdr != NULL)
	{
		size = rfc3095_ctxt->parse_static_next_hdr(context, rohc_remain_data,
		                                           rohc_remain_len, bits);
		if(size == -1)
		{
			rohc_decomp_warn(context, "cannot parse next header static part");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;
	}

	/* decode the dynamic part of the ROHC packet */
	if(dynamic_present)
	{
		/* decode the dynamic part of the outer IP header */
		size = parse_dynamic_part_ip(context, rohc_remain_data, rohc_remain_len,
		                             &bits->outer_ip, &rfc3095_ctxt->list_decomp1);
		if(size == -1)
		{
			rohc_decomp_warn(context, "cannot parse outer IP dynamic part");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;

		/* parse the dynamic part of the next header header if necessary */
		if(rfc3095_ctxt->parse_dyn_next_hdr != NULL)
		{
			size = rfc3095_ctxt->parse_dyn_next_hdr(context, rohc_remain_data,
			                                        rohc_remain_len, bits);
			if(size == -1)
			{
				rohc_decomp_warn(context, "cannot parse next header dynamic part");
				goto error;
			}
#ifndef __clang_analyzer__ /* silent warning about dead increment */
			rohc_remain_data += size;
			rohc_remain_len -= size;
#endif
			*rohc_hdr_len += size;
		}
	}
	else if(context->state != ROHC_DECOMP_STATE_FC)
	{
		/* in 'Static Context' or 'No Context' state and the packet does not
		 * contain a dynamic part */
		rohc_decomp_warn(context, "receive IR packet without a dynamic part, "
		                 "but not in Full Context state");
		goto error;
	}

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* invalid CRC-STATIC cache since some STATIC fields may have changed */
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	/* IR packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse the IP static part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param context     The decompression context
 * @param packet      The ROHC packet to parse
 * @param length      The length of the ROHC packet
 * @param bits        OUT: The bits extracted from the IP static part
 * @return            The number of bytes read in the ROHC packet,
 *                    -1 in case of failure
 */
static int parse_static_part_ip(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const packet,
                                const size_t length,
                                struct rohc_extr_ip_bits *const bits)
{
	int read; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the IP version */
	if(length < 1)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* retrieve the IP version */
	bits->version = GET_BIT_4_7(packet);

	/* reject non IPv4/IPv6 packets */
	if(bits->version != IPV4)
	{
		rohc_decomp_warn(context, "unsupported IP version (%d)", bits->version);
		goto error;
	}

	/* decode the static part of the IP header depending on the IP version */
	if(bits->version == IPV4)
	{
		read = parse_static_part_ipv4(context, packet, length, bits);
	}

	return read;

error:
	return -1;
}


/**
 * @brief Parse the IPv4 static part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details.
 *
 * @param context  The decompression context
 * @param packet   The ROHC packet to parse
 * @param length   The length of the ROHC packet
 * @param bits     OUT: The bits extracted from the IPv4 static part
 * @return         The number of bytes read in the ROHC packet,
 *                 -1 in case of failure
 */
static int parse_static_part_ipv4(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *packet,
                                  const size_t length,
                                  struct rohc_extr_ip_bits *const bits)
{
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the IPv4 static part */
	if(length < 10)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* IP version already read by \ref parse_static_part_ip */
	rohc_decomp_debug(context, "IP Version = %d", bits->version);
	packet++;
	read++;

	/* read the protocol number */
	bits->proto = GET_BIT_0_7(packet);
	bits->proto_nr = 8;
	rohc_decomp_debug(context, "Protocol = 0x%02x", bits->proto);
	packet++;
	read++;

	/* read the source IP address */
	memcpy(bits->saddr, packet, 4);
	bits->saddr_nr = 32;
	rohc_decomp_debug(context, "Source Address = " IPV4_ADDR_FORMAT,
	                  IPV4_ADDR_RAW(bits->saddr));
	packet += 4;
	read += 4;

	/* read the destination IP address */
	memcpy(bits->daddr, packet, 4);
	bits->daddr_nr = 32;
	rohc_decomp_debug(context, "Destination Address = " IPV4_ADDR_FORMAT,
	                  IPV4_ADDR_RAW(bits->daddr));
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += 4;
#endif
	read += 4;

	return read;

error:
	return -1;
}

/**
 * @brief Parse the IP dynamic part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param context     The decompression context
 * @param packet      The ROHC packet to parse
 * @param length      The length of the ROHC packet
 * @param bits        OUT: The bits extracted from the IP dynamic part
 * @param list_decomp The list decompressor (only for IPv6)
 * @return            The number of bytes read in the ROHC packet,
 *                    -1 in case of failure
 */
static int parse_dynamic_part_ip(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const packet,
                                 const size_t length,
                                 struct rohc_extr_ip_bits *const bits,
                                 struct list_decomp *const list_decomp)
{
	assert(list_decomp->profile_id>=0);
	int read; /* number of bytes read from the packet */

	/* decode the dynamic part of the IP header depending on the IP version */
	if(bits->version == IPV4)
	{
		read = parse_dynamic_part_ipv4(context, packet, length, bits);
	}

	return read;
}


/**
 * @brief Decode the IPv4 dynamic part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details. Generic extension header list is not
 * managed yet.
 * See 3.3 in RFC 3843 for details on the Static IP Identifier (SID) flag.
 *
 * \verbatim

Dynamic part:

      +---+---+---+---+---+---+---+---+
      |        Type of Service        |
      +---+---+---+---+---+---+---+---+
      |         Time to Live          |
      +---+---+---+---+---+---+---+---+
      /        Identification         /   2 octets, sent verbatim
      +---+---+---+---+---+---+---+---+
      | DF|RND|NBO|SID|       0       |
      +---+---+---+---+---+---+---+---+
      / Generic extension header list /  variable length
      +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context  The decompression context
 * @param packet   The ROHC packet to decode
 * @param length   The length of the ROHC packet
 * @param bits     OUT: The bits extracted from the IP dynamic part
 * @return         The number of bytes read in the ROHC packet,
 *                 -1 in case of failure
 */
static int parse_dynamic_part_ipv4(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *packet,
                                   const size_t length,
                                   struct rohc_extr_ip_bits *const bits)
{
	/* The size (in bytes) of the IPv4 dynamic part:
	 *
	 *   1 (TOS) + 1 (TTL) + 2 (IP-ID) + 1 (flags) + 1 (header list) = 6 bytes
	 *
	 * The size of the generic extension header list field is considered
	 * constant because generic extension header list is not supported yet and
	 * thus 1 byte of zero is used. */
	const size_t ipv4_dyn_size = 6;
	int read = 0; /* number of bytes read from the packet */

	/* check the minimal length to decode the IPv4 dynamic part */
	if(length < ipv4_dyn_size)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* read the TOS field */
	bits->tos = GET_BIT_0_7(packet);
	bits->tos_nr = 8;
	rohc_decomp_debug(context, "TOS = 0x%02x", bits->tos);
	packet++;
	read++;

	/* read the TTL field */
	bits->ttl = GET_BIT_0_7(packet);
	bits->ttl_nr = 8;
	rohc_decomp_debug(context, "TTL = 0x%02x", bits->ttl);
	packet++;
	read++;

	/* read the IP-ID field */
	bits->id = GET_NEXT_16_BITS(packet);
	bits->id_nr = 16;
	bits->is_id_enc = false;
	rohc_decomp_debug(context, "IP-ID = 0x%04x", bits->id);
	packet += 2;
	read += 2;

	/* read the DF flag */
	bits->df = GET_REAL(GET_BIT_7(packet));
	bits->df_nr = 1;

	/* read the RND flag */
	bits->rnd = GET_REAL(GET_BIT_6(packet));
	bits->rnd_nr = 1;

	/* read the NBO flag */
	bits->nbo = GET_REAL(GET_BIT_5(packet));
	bits->nbo_nr = 1;

	/* read the SID flag */
	bits->sid = GET_REAL(GET_BIT_4(packet));
	bits->sid_nr = 1;

	rohc_decomp_debug(context, "DF = %d, RND = %d, NBO = %d, SID = %d",
	                  bits->df, bits->rnd, bits->nbo, bits->sid);
	packet++;
	read++;

	/* generic extension header list is not managed yet,
	   ignore the byte which should be set to 0 */
	if(GET_BIT_0_7(packet) != 0x00)
	{
		rohc_decomp_warn(context, "generic extension header list not supported "
		                 "yet");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet++;
#endif
	read++;

	return read;

error:
	return -1;
}

/**
 * @brief Get the reference SN value of the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference SN value
 */
uint32_t rohc_decomp_rfc3095_get_sn(const struct rohc_decomp_ctxt *const context)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	return rohc_lsb_get_ref(&rfc3095_ctxt->sn_lsb_ctxt, ROHC_LSB_REF_0);
}


/**
 * @brief Parse one UO-0 header
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UO-0 (5.7.1)

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 0 |      SN       |    CRC    |
    +===+===+===+===+===+===+===+===+

 Part 4 is empty.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param rohc_length          The length of the ROHC packet
 * @param large_cid_len        The length of the optional large CID field
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc        The CRC bits extracted from the UO-0 header
 * @param[out] bits            The bits extracted from the UO-0 header
 * @param[out] rohc_hdr_len    The length of the ROHC header (in bytes)
 * @return                     true if UO-0 is successfully parsed,
 *                             false otherwise
 */
static bool parse_uo0(const struct rohc_decomp_ctxt *const context,
                      const uint8_t *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_decomp_crc *const extr_crc,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const uint8_t *rohc_remain_data;
	size_t rohc_remain_len;

	assert(rfc3095_ctxt != NULL);
	assert(rohc_packet != NULL);
	assert(packet_type != NULL);
	assert((*packet_type) == ROHC_PACKET_UO_0);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(rfc3095_ctxt, bits);

	/* check packet usage */
	assert(context->state == ROHC_DECOMP_STATE_FC);

	/* check if the ROHC packet is large enough to parse parts 2 and 3 */
	if(rohc_remain_len < (1 + large_cid_len))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* part 2: 1-bit "0" + 4-bit SN + 3-bit CRC */
	assert(GET_BIT_7(rohc_remain_data) == 0);
	bits->sn = GET_BIT_3_6(rohc_remain_data);
	bits->sn_nr = 4;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x", bits->sn_nr, bits->sn);
	extr_crc->type = ROHC_CRC_TYPE_3;
	extr_crc->bits = GET_BIT_0_2(rohc_remain_data);
	extr_crc->bits_nr = 3;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x",
	                  extr_crc->bits_nr, extr_crc->bits);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: no remainder of base header for UO-0 packet */
	/* part 5: no extension for UO-0 packet */

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(context, rohc_remain_data, rohc_remain_len, bits,
	                       &rohc_remainder_len))
	{
		rohc_decomp_warn(context, "failed to parse UO* remainder");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead increment */
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
#endif
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO-0 packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one UO-1 header for non-RTP profiles
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UO-1 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |         IP-ID         |
    +===+===+===+===+===+===+===+===+
 4  |        SN         |    CRC    |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param rohc_length          The length of the ROHC packet
 * @param large_cid_len        The length of the optional large CID field
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc        The CRC bits extracted from the UO-1 header
 * @param[out] bits            The bits extracted from the UO-1 header
 * @param[out] rohc_hdr_len    The length of the ROHC header (in bytes)
 * @return                     true if UO-1 is successfully parsed,
 *                             false otherwise
 */
static bool parse_uo1(const struct rohc_decomp_ctxt *const context,
                      const uint8_t *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_decomp_crc *const extr_crc,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const uint8_t *rohc_remain_data;
	size_t rohc_remain_len;

	/* which IP header is the innermost IPv4 header with non-random IP-ID ? */
	ip_header_pos_t innermost_ipv4_non_rnd;

	assert(context != NULL);
	rfc3095_ctxt = context->persist_ctxt;
	assert(rohc_packet != NULL);
	assert(packet_type != NULL);
	assert((*packet_type) == ROHC_PACKET_UO_1);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(rfc3095_ctxt, bits);

	/* determine which IP header is the innermost IPv4 header with
	 * value(RND) = 0 */
	if(is_ipv4_non_rnd_pkt(&bits->outer_ip))
	{
		/* outer IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;
	}
	else
	{
		/* no IPv4 header with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
	}

	/* check packet usage */
	assert(context->state == ROHC_DECOMP_STATE_FC);
	if(innermost_ipv4_non_rnd == ROHC_IP_HDR_NONE)
	{
		rohc_decomp_warn(context, "cannot use the UO-1 packet with no 'IPv4 "
		                 "header with non-random IP-ID'");
		goto error;
	}

	/* check if the rohc packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len <= (1 + large_cid_len))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* part 2: 2-bit "10" + 6-bit IP-ID */
	assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
	if(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST)
	{
		bits->outer_ip.id = GET_BIT_0_5(rohc_remain_data);
		bits->outer_ip.id_nr = 6;
		bits->outer_ip.is_id_enc = true;
		rohc_decomp_debug(context, "%zd IP-ID bits for IP header #%u = 0x%x",
		                  bits->outer_ip.id_nr, innermost_ipv4_non_rnd,
		                  bits->outer_ip.id);
	}
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: 5-bit SN + 3-bit CRC */
	bits->sn = GET_BIT_3_7(rohc_remain_data);
	bits->sn_nr = 5;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x", bits->sn_nr, bits->sn);
	extr_crc->type = ROHC_CRC_TYPE_3;
	extr_crc->bits = GET_BIT_0_2(rohc_remain_data);
	extr_crc->bits_nr = 3;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x",
	                  extr_crc->bits_nr, extr_crc->bits);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: extension only for UO-1-ID packet */

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(context, rohc_remain_data, rohc_remain_len, bits,
	                       &rohc_remainder_len))
	{
		rohc_decomp_warn(context, "failed to parse UO-1 remainder");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
#endif
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO-1 packet was successfully parsed */
	return true;

error:
	return false;
}

/**
 * @brief Parse one UOR-2 header for non-RTP profiles
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UOR-2 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        SN         |
    +===+===+===+===+===+===+===+===+
 4  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param rohc_length          The length of the ROHC packet
 * @param large_cid_len        The length of the optional large CID field
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc        The CRC bits extracted from the UOR-2 header
 * @param[out] bits            The bits extracted from the UOR-2 header
 * @param[out] rohc_hdr_len    The length of the ROHC header (in bytes)
 * @return                     true if UOR-2 is successfully parsed,
 *                             false otherwise
 */
static bool parse_uor2(const struct rohc_decomp_ctxt *const context,
                       const uint8_t *const rohc_packet,
                       const size_t rohc_length,
                       const size_t large_cid_len,
                       rohc_packet_t *const packet_type,
                       struct rohc_decomp_crc *const extr_crc,
                       struct rohc_extr_bits *const bits,
                       size_t *const rohc_hdr_len)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const uint8_t *rohc_remain_data = rohc_packet;
	size_t rohc_remain_len = rohc_length;

	assert(packet_type != NULL);
	assert((*packet_type) == ROHC_PACKET_UOR_2);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(rfc3095_ctxt, bits);

	/* check packet usage */
	assert(context->state != ROHC_DECOMP_STATE_NC);

	/* check if the ROHC packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len < (1 + large_cid_len + 1))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* part 2: 3-bit "110" + 5-bit SN */
	assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
	bits->sn = GET_BIT_0_4(rohc_remain_data);
	bits->sn_nr = 5;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x", bits->sn_nr, bits->sn);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: 7-bit CRC */
	extr_crc->type = ROHC_CRC_TYPE_7;
	extr_crc->bits = GET_BIT_0_6(rohc_remain_data);
	extr_crc->bits_nr = 7;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x",
	                  extr_crc->bits_nr, extr_crc->bits);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(context, rohc_remain_data, rohc_remain_len, bits,
	                       &rohc_remainder_len))
	{
		rohc_decomp_warn(context, "failed to parse UO* remainder");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
#endif
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UOR-2 packet was successfully parsed */
	return true;

error:
	return false;
}

/**
 * @brief Parse the remainder of the UO* header
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1, 2, 3, 4, and 5 are parsed in parent functions.
 * Parts 6 and 9 are parsed in this function.
 * Part 13 is parsed in profile-specific function.
 *
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param bits           OUT: The bits extracted from the UO* header
 * @param rohc_hdr_len   OUT: The size of the UO* header
 * @return               true if UO* is successfully parsed, false otherwise
 */
static bool parse_uo_remainder(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_extr_bits *const bits,
                               size_t *const rohc_hdr_len)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const uint8_t *rohc_remain_data;
	size_t rohc_remain_len;

	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* part 6: extract 16 outer IP-ID bits in case the outer IP-ID is random */
	if(is_ipv4_rnd_pkt(&bits->outer_ip))
	{
		/* outer IP-ID is random, read its full 16-bit value and ignore any
		   previous bits we may have read (they should be filled with zeroes) */

		/* check if the ROHC packet is large enough to read the outer IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_decomp_warn(context, "ROHC packet too small for random outer "
			                 "IP-ID bits (len = %zu)", rohc_remain_len);
			goto error;
		}

		/* sanity check: all bits that are above 16 bits should be zero */
		if(bits->outer_ip.id_nr > 0 && bits->outer_ip.id != 0)
		{
			rohc_decomp_warn(context, "bad packet format: outer IP-ID bits from "
			                 "the base ROHC header shall be filled with zeroes "
			                 "but 0x%x was found", bits->outer_ip.id);
		}

		/* retrieve the full outer IP-ID value */
		bits->outer_ip.id = rohc_ntoh16(GET_NEXT_16_BITS(rohc_remain_data));
		bits->outer_ip.id_nr = 16;
		bits->outer_ip.is_id_enc = true;

		rohc_decomp_debug(context, "replace any existing outer IP-ID bits with "
		                  "with the ones found at the end of the UO* packet "
		                  "(0x%x on %zd bits)", bits->outer_ip.id,
		                  bits->outer_ip.id_nr);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		*rohc_hdr_len += 2;
	}

	/* parts 7 and 8: not supported */

	/* parts 10, 11 and 12: not supported */

	/* part 13: decode the tail of UO* packet */
	if(rfc3095_ctxt->parse_uo_remainder != NULL)
	{
		int size;

		size = rfc3095_ctxt->parse_uo_remainder(context, rohc_remain_data,
		                                        rohc_remain_len, bits);
		if(size < 0)
		{
			rohc_decomp_warn(context, "cannot decode the remainder of UO* packet");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += size;
		rohc_remain_len -= size;
#endif
		*rohc_hdr_len += size;
	}

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO* remainder was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one IR-DYN packet
 *
 * \verbatim

 IR-DYN packet (5.7.7.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         : if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   0   0 | IR-DYN packet type
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /     0-2 octets of CID info    / 1-2 octets if for large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
 4  |            Profile            | 1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              | 1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /         Dynamic chain         / variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 7  |             SN                | 2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    :                               :
    /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param rohc_length          The length of the ROHC packet
 * @param large_cid_len        The length of the optional large CID field
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc        The CRC bits extracted from the IR-DYN header
 * @param[out] bits            The bits extracted from the IR-DYN header
 * @param[out] rohc_hdr_len    The length of the ROHC header (in bytes)
 * @return                     true if IR-DYN is successfully parsed,
 *                             false otherwise
 */
static bool parse_irdyn(const struct rohc_decomp_ctxt *const context,
                        const uint8_t *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_decomp_crc *const extr_crc,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const uint8_t *rohc_remain_data;
	size_t rohc_remain_len;

	/* helper variables for values returned by functions */
	int size;

	assert(rohc_packet != NULL);
	assert(packet_type != NULL);
	assert((*packet_type) == ROHC_PACKET_IR_DYN);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(rfc3095_ctxt, bits);
	extr_crc->type = ROHC_CRC_TYPE_NONE;

	/* packet must large enough for:
	 * IR-DYN type + (large CID + ) Profile ID + CRC */
	if(rohc_remain_len < (1 + large_cid_len + 2))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* skip the IR-DYN type, optional large CID bytes, and Profile ID */
	rohc_remain_data += large_cid_len + 2;
	rohc_remain_len -= large_cid_len + 2;
	*rohc_hdr_len += large_cid_len + 2;

	/* parse CRC */
	extr_crc->bits = GET_BIT_0_7(rohc_remain_data);
	extr_crc->bits_nr = 8;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x",
	                  extr_crc->bits_nr, extr_crc->bits);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* decode the dynamic part of the outer IP header */
	size = parse_dynamic_part_ip(context, rohc_remain_data, rohc_remain_len,
	                             &bits->outer_ip, &rfc3095_ctxt->list_decomp1);
	if(size == -1)
	{
		rohc_decomp_warn(context, "cannot decode the outer IP dynamic part");
		goto error;
	}
	rohc_remain_data += size;
	rohc_remain_len -= size;
	*rohc_hdr_len += size;

	/* parse the dynamic part of the next header if necessary */
	if(rfc3095_ctxt->parse_dyn_next_hdr != NULL)
	{
		size = rfc3095_ctxt->parse_dyn_next_hdr(context, rohc_remain_data,
		                                        rohc_remain_len, bits);
		if(size == -1)
		{
			rohc_decomp_warn(context, "cannot decode the next header dynamic part");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += size;
		rohc_remain_len -= size;
#endif
		*rohc_hdr_len += size;
	}

	/* invalid CRC-STATIC cache since some STATIC fields may have changed */
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	return true;

error:
	return false;
}

/**
 * @brief Build the uncompressed headers
 *
 * @todo check for uncomp_hdrs size before writing into it
 *
 * @param decomp                The ROHC decompressor
 * @param context               The decompression context
 * @param packet_type           The type of ROHC packet
 * @param extr_crc              The CRC bits extracted from the ROHC header
 * @param decoded               The values decoded from ROHC header
 * @param payload_len           The length of the packet payload
 * @param[out] uncomp_hdrs      The buffer to store the uncompressed headers
 * @param[out] uncomp_hdrs_len  The length of the uncompressed headers written
 *                              into the buffer
 * @return                      Possible values:
 *                               \li ROHC_STATUS_OK if headers are built
 *                                   successfully,
 *                               \li ROHC_STATUS_BAD_CRC if headers do not
 *                                   match CRC,
 *                               \li ROHC_STATUS_OUTPUT_TOO_SMALL if the
 *                                   output buffer is too small
 */
rohc_status_t rfc3095_decomp_build_hdrs(const struct rohc_decomp *const decomp,
                                        const struct rohc_decomp_ctxt *const context,
                                        const rohc_packet_t packet_type,
                                        const struct rohc_decomp_crc *const extr_crc,
                                        const struct rohc_decoded_values *const decoded,
                                        const size_t payload_len,
                                        struct rohc_buf *const uncomp_hdrs,
                                        size_t *const uncomp_hdrs_len)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	uint8_t *uncomp_hdrs_data = rohc_buf_data(*uncomp_hdrs);
	size_t uncomp_hdrs_max_len = rohc_buf_avail_len(*uncomp_hdrs);
	uint8_t *outer_ip_hdr;
	uint8_t *inner_ip_hdr;
	uint8_t *next_header;
	size_t ip_payload_len = 0;

	*uncomp_hdrs_len = 0;

	/* build the IP headers */
	size_t ip_hdr_len;

	rohc_decomp_debug(context, "length of transport header = %u bytes",
						rfc3095_ctxt->outer_ip_changes->next_header_len);
	ip_payload_len += rfc3095_ctxt->outer_ip_changes->next_header_len;
	ip_payload_len += payload_len;

	/* build the single IP header */
	if(!build_uncomp_ip(context, decoded->outer_ip, uncomp_hdrs_data,
						uncomp_hdrs_max_len, &ip_hdr_len, ip_payload_len,
						&rfc3095_ctxt->list_decomp1))
	{
		rohc_decomp_warn(context, "failed to build the IP header");
		goto error_output_too_small;
	}
	outer_ip_hdr = uncomp_hdrs_data;
	inner_ip_hdr = NULL;
	uncomp_hdrs_data += ip_hdr_len;
	*uncomp_hdrs_len += ip_hdr_len;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	uncomp_hdrs_max_len -= ip_hdr_len;
#endif
	uncomp_hdrs->len += ip_hdr_len;

	/* build the next header if present */
	next_header = uncomp_hdrs_data;
	if(rfc3095_ctxt->build_next_header != NULL)
	{
		/* TODO: check uncomp_hdrs max size */
		size_t size = rfc3095_ctxt->build_next_header(context, decoded,
		                                              uncomp_hdrs_data, payload_len);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		uncomp_hdrs_data += size;
#endif
		*uncomp_hdrs_len += size;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		uncomp_hdrs_max_len -= size;
#endif
		uncomp_hdrs->len += size;
	}

	/* compute CRC on uncompressed headers if asked */
	if(extr_crc->type != ROHC_CRC_TYPE_NONE)
	{
		bool crc_ok;

		assert(extr_crc->bits_nr > 0);

		crc_ok = check_uncomp_crc(decomp, context, outer_ip_hdr, inner_ip_hdr,
		                          next_header, extr_crc->type, extr_crc->bits);
		if(!crc_ok)
		{
			rohc_decomp_warn(context, "CRC detected a decompression failure for "
			                 "packet of type %s in state %s and mode %s",
			                 rohc_get_packet_descr(packet_type),
			                 rohc_decomp_get_state_descr(context->state),
			                 rohc_get_mode_descr(context->mode));
			if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
			{
				rohc_dump_buf(decomp->trace_callback, decomp->trace_callback_priv,
				              ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
				              "uncompressed headers", outer_ip_hdr, *uncomp_hdrs_len);
			}
			goto error_crc;
		}
	}

	return ROHC_STATUS_OK;

error_crc:
	return ROHC_STATUS_BAD_CRC;
error_output_too_small:
	return ROHC_STATUS_OUTPUT_TOO_SMALL;
}


/**
 * @brief Build an uncompressed IP header.
 *
 * @param context               The decompression context
 * @param decoded               The decoded IPv4 fields
 * @param dest                  The buffer to store the IP header
 * @param uncomp_hdrs_max_len   The max length of the IP header
 * @param[out] uncomp_hdrs_len  The length of the IPv4 header
 * @param payload_size          The length of the IP payload
 * @param list_decomp           The list decompressor (IPv6 only)
 * @return                      true if the IP header is successfully built,
 *                              false if an error occurs
 */
static bool build_uncomp_ip(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_decoded_ip_values decoded,
                            uint8_t *const dest,
                            const size_t uncomp_hdrs_max_len,
                            size_t *const uncomp_hdrs_len,
                            const size_t payload_size,
                            const struct list_decomp *const list_decomp)
{
	bool is_ok;

	assert(list_decomp==NULL || list_decomp!=NULL);

	if(decoded.version == IPV4)
	{
		is_ok = build_uncomp_ipv4(context, decoded, dest, uncomp_hdrs_max_len,
		                          uncomp_hdrs_len, payload_size);
	}

	return is_ok;
}


/**
 * @brief Build an uncompressed IPv4 header.
 *
 * @param context               The decompression context
 * @param decoded               The decoded IPv4 fields
 * @param dest                  The buffer to store the IPv4 header
 * @param uncomp_hdrs_max_len   The max length of the IPv4 header
 * @param[out] uncomp_hdrs_len  The length of the IPv4 header
 * @param payload_size          The length of the IPv4 payload
 * @return                      true if the IPv4 header is successfully built,
 *                              false if an error occurs
 */
static bool build_uncomp_ipv4(const struct rohc_decomp_ctxt *const context,
                              const struct rohc_decoded_ip_values decoded,
                              uint8_t *const dest,
                              const size_t uncomp_hdrs_max_len,
                              size_t *const uncomp_hdrs_len,
                              const size_t payload_size)
{
	struct ipv4_hdr *const ip = (struct ipv4_hdr *) dest;

	if(uncomp_hdrs_max_len < sizeof(struct ipv4_hdr))
	{
		rohc_decomp_warn(context, "uncompressed packet too small for IPv4 "
		                 "header");
		goto error;
	}

	/* static-known fields */
	ip->ihl = 5;

	/* static fields */
	ip->version = decoded.version;
	ip->protocol = decoded.proto;
	memcpy(&ip->saddr, decoded.saddr, 4);
	memcpy(&ip->daddr, decoded.daddr, 4);

	/* dynamic fields */
	ip->tos = decoded.tos;
	ip->id = rohc_hton16(decoded.id);
	if(!decoded.nbo)
	{
		ip->id = swab16(ip->id);
	}
	ip->frag_off = 0;
	ip->df = decoded.df;
	ip->ttl = decoded.ttl;

	/* inferred fields */
	ip->tot_len = rohc_hton16(payload_size + ip->ihl * 4);
	rohc_decomp_debug(context, "Total Length = 0x%04x (IHL * 4 + %zu)",
	                  rohc_ntoh16(ip->tot_len), payload_size);
	ip->check = 0;
	ip->check = ip_fast_csum(dest, ip->ihl);
	rohc_decomp_debug(context, "IP checksum = 0x%04x",
	                  rohc_ntoh16(ip->check));

	*uncomp_hdrs_len = sizeof(struct ipv4_hdr);
	return true;

error:
	return false;
}

/**
 * @brief Check whether the CRC on uncompressed header is correct or not
 *
 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
 *       if the CRC-STATIC fields did not change.
 *
 * @param decomp        The ROHC decompressor
 * @param context       The decompression context
 * @param outer_ip_hdr  The outer IP header
 * @param inner_ip_hdr  The inner IP header if it exists, NULL otherwise
 * @param next_header   The transport header, eg. UDP
 * @param crc_type      The type of CRC
 * @param crc_packet    The CRC extracted from the ROHC header
 * @return              true if the CRC is correct, false otherwise
 */
static bool check_uncomp_crc(const struct rohc_decomp *const decomp,
                             const struct rohc_decomp_ctxt *const context,
                             const uint8_t *const outer_ip_hdr,
                             const uint8_t *const inner_ip_hdr,
                             const uint8_t *const next_header,
                             const rohc_crc_type_t crc_type,
                             const uint8_t crc_packet)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	const uint8_t *crc_table;
	uint8_t crc_computed;

	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->persist_ctxt != NULL);
	rfc3095_ctxt = context->persist_ctxt;
	assert(outer_ip_hdr != NULL);
	assert(next_header != NULL);
	assert(crc_type != ROHC_CRC_TYPE_NONE);

	/* determine the initial value and the pre-computed table for the CRC */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_3:
			crc_computed = CRC_INIT_3;
			crc_table = decomp->crc_table_3;
			break;
		case ROHC_CRC_TYPE_7:
			crc_computed = CRC_INIT_7;
			crc_table = decomp->crc_table_7;
			break;
		case ROHC_CRC_TYPE_8:
			crc_computed = CRC_INIT_8;
			crc_table = decomp->crc_table_8;
			break;
		case ROHC_CRC_TYPE_NONE:
		default:
			rohc_decomp_warn(context, "unknown CRC type %d", crc_type);
			assert(0);
			goto error;
	}

	/* compute the CRC on CRC-STATIC fields of built uncompressed headers */
	if(rfc3095_ctxt->is_crc_static_3_cached_valid && crc_type == ROHC_CRC_TYPE_3)
	{
		crc_computed = rfc3095_ctxt->crc_static_3_cached;
		rohc_decomp_debug(context, "use CRC-STATIC-3 = 0x%x from cache", crc_computed);
	}
	else if(rfc3095_ctxt->is_crc_static_7_cached_valid && crc_type == ROHC_CRC_TYPE_7)
	{
		crc_computed = rfc3095_ctxt->crc_static_7_cached;
		rohc_decomp_debug(context, "use CRC-STATIC-7 = 0x%x from cache", crc_computed);
	}
	else
	{
		crc_computed = rfc3095_ctxt->compute_crc_static(outer_ip_hdr, inner_ip_hdr,
		                                                next_header, crc_type,
		                                                crc_computed, crc_table);
		rohc_decomp_debug(context, "compute CRC-STATIC-%d = 0x%x from packet",
		                  crc_type, crc_computed);

		switch(crc_type)
		{
			case ROHC_CRC_TYPE_3:
				rfc3095_ctxt->crc_static_3_cached = crc_computed;
				rfc3095_ctxt->is_crc_static_3_cached_valid = true;
				break;
			case ROHC_CRC_TYPE_7:
				rfc3095_ctxt->crc_static_7_cached = crc_computed;
				rfc3095_ctxt->is_crc_static_7_cached_valid = true;
				break;
			default:
				break;
		}
	}

	/* compute the CRC on CRC-DYNAMIC fields of built uncompressed headers */
	crc_computed = rfc3095_ctxt->compute_crc_dynamic(outer_ip_hdr, inner_ip_hdr,
	                                                 next_header, crc_type,
	                                                 crc_computed, crc_table);
	rohc_decomp_debug(context, "CRC-%d on uncompressed header = 0x%x",
	                  crc_type, crc_computed);

	/* does the computed CRC match the one in packet? */
	if(crc_computed != crc_packet)
	{
		rohc_decomp_warn(context, "CRC failure (computed = 0x%02x, packet = "
		                 "0x%02x)", crc_computed, crc_packet);
		goto error;
	}

	/* computed CRC matches the one in packet */
	return true;

error:
	return false;
}


/**
 * @brief Attempt a packet/context repair upon CRC failure
 *
 * @param decomp             The ROHC decompressor
 * @param context            The decompression context
 * @param pkt_arrival_time   The arrival time of the ROHC packet that caused
 *                           the CRC failure
 * @param[in,out] crc_corr   The context for corrections upon CRC failures
 * @param[in,out] extr_bits  The bits extracted from the ROHC header
 * @return                   true if repair is possible, false if not
 */
bool rfc3095_decomp_attempt_repair(const struct rohc_decomp *const decomp,
                                   const struct rohc_decomp_ctxt *const context,
                                   const struct rohc_ts pkt_arrival_time,
                                   struct rohc_decomp_crc_corr_ctxt *const crc_corr,
                                   struct rohc_extr_bits *const extr_bits)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	const uint32_t sn_ref_0 = rohc_lsb_get_ref(&rfc3095_ctxt->sn_lsb_ctxt,
	                                           ROHC_LSB_REF_0);
	const uint32_t sn_ref_minus_1 = rohc_lsb_get_ref(&rfc3095_ctxt->sn_lsb_ctxt,
	                                                 ROHC_LSB_REF_MINUS_1);
	bool verdict = false;

	/* do not try to repair packet/context if feature is disabled */
	if((decomp->features & ROHC_DECOMP_FEATURE_CRC_REPAIR) == 0)
	{
		rohc_decomp_warn(context, "CID %zu: CRC repair: feature disabled",
		                 context->cid);
		goto skip;
	}

	/* do not try to repair packet/context if repair is already in action */
	if(crc_corr->algo != ROHC_DECOMP_CRC_CORR_SN_NONE)
	{
		rohc_decomp_warn(context, "CID %zu: CRC repair: repair already in action",
		                 context->cid);
		goto skip;
	}

	/* no correction attempt shall be already running */
	assert(crc_corr->counter == 0);

	/* try to guess the correct SN value in case of failure */
	rohc_decomp_warn(context, "CID %zu: CRC repair: attempt to correct SN",
	                 context->cid);

	/* step b of RFC3095, §5.3.2.2.4. Correction of SN LSB wraparound:
	 *   When decompression fails, the decompressor computes the time
	 *   elapsed between the arrival of the previous, correctly decompressed
	 *   packet and the current packet.
	 *
	 * step c of RFC3095, §5.3.2.2.4. Correction of SN LSB wraparound:
	 *   If wraparound has occurred, INTERVAL will correspond to at least
	 *   2^k inter-packet times, where k is the number of SN bits in the
	 *   current header. */
	if(is_sn_wraparound(pkt_arrival_time, crc_corr->arrival_times,
	                    crc_corr->arrival_times_nr, crc_corr->arrival_times_index,
	                    extr_bits->sn_nr, rfc3095_ctxt->sn_lsb_p))
	{
		rohc_decomp_warn(context, "CID %zu: CRC repair: CRC failure seems to "
		                 "be caused by a sequence number LSB wraparound",
		                 context->cid);

		crc_corr->algo = ROHC_DECOMP_CRC_CORR_SN_WRAP;

		/* step d of RFC3095, §5.3.2.2.4. Correction of SN LSB wraparound:
		 *   add 2^k to the reference SN and attempts to decompress the
		 *   packet using the new reference SN */
		extr_bits->sn_ref_offset = (1 << extr_bits->sn_nr);
		rohc_decomp_warn(context, "CID %zu: CRC repair: try adding 2^k = 2^%zu "
		                 "= %u to reference SN (ref 0 = %u)", context->cid,
		                 extr_bits->sn_nr, extr_bits->sn_ref_offset, sn_ref_0);
	}
	else if(sn_ref_0 != sn_ref_minus_1)
	{
		rohc_decomp_warn(context, "CID %zu: CRC repair: CRC failure seems to "
		                 "be caused by an incorrect SN update", context->cid);

		crc_corr->algo = ROHC_DECOMP_CRC_CORR_SN_UPDATES;

		/* step d of RFC3095, §5.3.2.2.5. Repair of incorrect SN updates:
		 *   If the header generated in b. does not pass the CRC test, and the
		 *   SN (SN curr2) generated when using ref -1 as the reference is
		 *   different from SN curr1, an additional decompression attempt is
		 *   performed based on SN curr2 as the decompressed SN. */
		extr_bits->lsb_ref_type = ROHC_LSB_REF_MINUS_1;
		rohc_decomp_warn(context, "CID %zu: CRC repair: try using ref -1 (%u) "
		                 "as reference SN instead of ref 0 (%u)",
		                 context->cid, sn_ref_minus_1, sn_ref_0);
	}
	else
	{
		/* step e of RFC3095, §5.3.2.2.5. Repair of incorrect SN updates:
		 *   If the decompressed header generated in b. does not pass the CRC
		 *   test and SN curr2 is the same as SN curr1, an additional
		 *   decompression attempt is not useful and is not attempted. */
		rohc_decomp_warn(context, "CID %zu: CRC repair: repair is not useful",
		                 context->cid);
		goto skip;
	}

	/* packet/context correction is going to be attempted, 3 packets with
	 * correct CRC are required to accept the correction */
	crc_corr->counter = 3;
	verdict = true;

skip:
	return verdict;
}


/**
 * @brief Is SN wraparound possible?
 *
 * According to RFC3095, §5.3.2.2.4, step c, SN wraparound is possible if the
 * inter-packet interval of the current packet is at least 2^k times the
 * nominal inter-packet interval (with k the number of SN bits in the current
 * header).
 *
 * However SN wraparound may happen sooner depending on the shift parameter p
 * of the W-LSB algorithm. If p is large, the interpretation interval is shifted
 * on the left: the positive part of the interpretation interval is smaller.
 * Less (lost) packets are needed to cause a wraparound.
 *
 * The 'width of the positive part of the interpretation interval' (2^k - p) is
 * used instead of the 'width of the full interpretation interval' (2^k).
 *
 * A -10% marge is taken to handle problems due to clock precision.
 *
 * @param cur_arrival_time     The arrival time of the current packet
 * @param arrival_times        The arrival times for the last packets
 * @param arrival_times_nr     The number of arrival times for last packets
 * @param arrival_times_index  The index for the arrival time of the next
 *                             packet
 * @param k                    The number of bits for SN
 * @param p                    The shift parameter p for SN
 * @return                     Whether SN wraparound is possible or not
 */
static bool is_sn_wraparound(const struct rohc_ts cur_arrival_time,
                             const struct rohc_ts arrival_times[ROHC_MAX_ARRIVAL_TIMES],
                             const size_t arrival_times_nr,
                             const size_t arrival_times_index,
                             const size_t k,
                             const rohc_lsb_shift_t p)
{
	const size_t arrival_times_index_last =
		(arrival_times_index + ROHC_MAX_ARRIVAL_TIMES - 1) % ROHC_MAX_ARRIVAL_TIMES;
	uint64_t cur_interval; /* in microseconds */
	uint64_t avg_interval; /* in microseconds */
	uint64_t min_interval; /* in microseconds */

	/* cannot use correction for SN wraparound if no arrival time was given
	 * for the current packet, or if too few packets were received yet */
	if((cur_arrival_time.sec == 0 && cur_arrival_time.nsec == 0) ||
	   arrival_times_nr < ROHC_MAX_ARRIVAL_TIMES)
	{
		goto error;
	}

	/* compute inter-packet arrival time for current packet */
	cur_interval = rohc_time_interval(arrival_times[arrival_times_index_last],
	                                  cur_arrival_time);

	/* compute average inter-packet arrival time for last packets */
	avg_interval = rohc_time_interval(arrival_times[arrival_times_index],
	                                  arrival_times[arrival_times_index_last]);
	avg_interval /= ROHC_MAX_ARRIVAL_TIMES - 1;

	/* compute the minimum inter-packet interval that the current interval
	 * shall exceed so that SN wraparound is detected */
	if(rohc_interval_compute_p(k, p) >= (1 << k))
	{
		goto error;
	}
	min_interval = ((1 << k) - rohc_interval_compute_p(k, p)) * avg_interval;

	/* subtract 10% to handle problems related to clock precision */
	min_interval -= min_interval * 10 / 100;

	/* enough time elapsed for SN wraparound? */
	return (cur_interval >= min_interval);

error:
	return false;
}


/**
 * @brief Decode values from extracted bits
 *
 * The following values are decoded:
 *  - SN
 *  - fields related to the outer IP header
 *  - fields related to the inner IP header (if it exists)
 *
 * Other fields may be decoded by the profile-specific callback named
 * decode_values_from_bits.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context       The decompression context
 * @param bits          The bits extracted from the ROHC packet
 * @param payload_len   The length of the packet payload (in bytes)
 * @param[out] decoded  The corresponding decoded values
 * @return              true if decoding is successful, false otherwise
 */
bool rfc3095_decomp_decode_bits(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_extr_bits *const bits,
                                const size_t payload_len __attribute__((unused)),
                                struct rohc_decoded_values *const decoded)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	bool decode_ok;

	decoded->is_context_reused = bits->is_context_reused;

	/* decode context mode */
	if(bits->mode_nr > 0 && bits->mode != 0)
	{
		decoded->mode = bits->mode;
	}
	else
	{
		decoded->mode = context->mode;
	}

	/* decode SN */
	if(!bits->is_sn_enc)
	{
		/* SN is not encoded: either take the value unchanged or deduce it */
		if(bits->sn_nr == 16 || bits->sn_nr == 32)
		{
			decoded->sn = bits->sn; /* take packet value unchanged */
		}
		else if(bits->sn_nr == 0)
		{
			decoded->sn = context->profile->get_sn(context) + 1; /* deduction */
			decoded->sn &= 0xffff;
		}
		else
		{
			assert(0);
			goto error;
		}
	}
	else
	{
		/* decode SN from packet bits and context */
		decode_ok = rohc_lsb_decode(&rfc3095_ctxt->sn_lsb_ctxt, bits->lsb_ref_type,
		                            bits->sn_ref_offset, bits->sn, bits->sn_nr,
		                            rfc3095_ctxt->sn_lsb_p, &decoded->sn);
		if(!decode_ok)
		{
			rohc_decomp_warn(context, "failed to decode %zu SN bits 0x%x",
			                 bits->sn_nr, bits->sn);
			goto error;
		}
	}
	rohc_decomp_debug(context, "decoded SN = %u / 0x%x (nr bits = %zd, "
	                  "bits = %u / 0x%x)", decoded->sn, decoded->sn,
	                  bits->sn_nr, bits->sn, bits->sn);

	/* maybe current packet changed the number of IP headers */
	decoded->multiple_ip = bits->multiple_ip;

	/* decode fields related to the outer IP header */
	decode_ok = decode_ip_values_from_bits(context, rfc3095_ctxt->outer_ip_changes,
	                                       &rfc3095_ctxt->outer_ip_id_offset_ctxt,
	                                       decoded->sn, bits->lsb_ref_type,
	                                       &bits->outer_ip, "outer", 1,
	                                       &decoded->outer_ip);
	if(!decode_ok)
	{
		rohc_decomp_warn(context, "failed to decode bits extracted for outer "
		                 "IP header");
		goto error;
	}

	/* decode fields of next header if required */
	if(rfc3095_ctxt->decode_values_from_bits != NULL)
	{
		decode_ok = rfc3095_ctxt->decode_values_from_bits(context, bits, decoded);
		if(!decode_ok)
		{
			rohc_decomp_warn(context, "failed to decode fields of the next header");
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Decode IP values from extracted bits
 *
 * @param context       The decompression context
 * @param ctxt          The decompression context for the IP header
 * @param ip_id_decode  The context for decoding IP-ID offset
 * @param decoded_sn    The SN that was decoded
 * @param lsb_ref_type  The reference value to use to decode LSB values
 *                      (used for context repair upon CRC failure)
 * @param bits          The IP bits extracted from ROHC header (all headers
 *                      included: static/dynamic chains, UO* base header,
 *                      UO* extension header, UO* remainder header)
 * @param descr         The description of the IP header
 * @param ip_hdr_pos    The position of the IP header (1 = outer, 2 = inner)
 * @param decoded       OUT: The corresponding decoded IP values
 * @return              true if decoding is successful, false otherwise
 */
static bool decode_ip_values_from_bits(const struct rohc_decomp_ctxt *const context,
                                       const struct rohc_decomp_rfc3095_changes *const ctxt,
                                       const struct ip_id_offset_decode *const ip_id_decode,
                                       const uint32_t decoded_sn,
                                       const rohc_lsb_ref_t lsb_ref_type,
                                       const struct rohc_extr_ip_bits *const bits,
                                       const char *const descr,
                                       const size_t ip_hdr_pos,
                                       struct rohc_decoded_ip_values *const decoded)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	const bool new_inner_ip_hdr = !!(ip_hdr_pos == 2 && !rfc3095_ctxt->multiple_ip);
	
	assert(ctxt != NULL);
	assert(decoded != NULL);

	/* IP version (always present in extracted bits) */
	decoded->version = bits->version;

	rohc_decomp_debug(context, "decode %s IPv%u header", descr, decoded->version);

	/* TOS/TC */
	if(bits->tos_nr > 0)
	{
		/* take value from base header */
		decoded->tos = bits->tos;
	}
	else if(new_inner_ip_hdr)
	{
		rohc_decomp_warn(context, "failed to decode inner IP header: no information "
		                 "in context and no TOS/TC bit in packet");
		goto error;
	}
	else
	{
		/* keep context value */
		decoded->tos = ip_get_tos(&ctxt->ip);
	}
	rohc_decomp_debug(context, "decoded %s TOS/TC = %d", descr, decoded->tos);

	/* TTL/HL */
	if(bits->ttl_nr > 0)
	{
		/* take value from base header */
		decoded->ttl = bits->ttl;
	}
	else if(new_inner_ip_hdr)
	{
		rohc_decomp_warn(context, "failed to decode inner IP header: no information "
		                 "in context and no TTL/HL bit in packet");
		goto error;
	}
	else
	{
		/* keep context value */
		decoded->ttl = ip_get_ttl(&ctxt->ip);
	}
	rohc_decomp_debug(context, "decoded %s TTL/HL = %d", descr, decoded->ttl);

	/* protocol/NH */
	if(bits->proto_nr > 0)
	{
		/* take value from base header */
		decoded->proto = bits->proto;
	}
	else if(new_inner_ip_hdr)
	{
		rohc_decomp_warn(context, "failed to decode inner IP header: no information "
		                 "in context and no protocol/NH bit in packet");
		goto error;
	}
	else
	{
		/* keep context value */
		decoded->proto = ip_get_protocol(&ctxt->ip);
	}
	rohc_decomp_debug(context, "decoded %s protocol/NH = %d", descr,
	                  decoded->proto);

	/* version specific fields */
	if(decoded->version == IPV4)
	{
		/* NBO flag */
		if(bits->nbo_nr > 0)
		{
			/* take value from base header */
			decoded->nbo = bits->nbo;
		}
		else if(new_inner_ip_hdr)
		{
			rohc_decomp_warn(context, "failed to decode inner IP header: no "
			                 "information in context and no NBO bit in packet");
			goto error;
		}
		else
		{
			/* keep context value */
			decoded->nbo = ctxt->nbo;
		}
		rohc_decomp_debug(context, "decoded %s NBO = %d", descr, decoded->nbo);

		/* RND flag */
		if(bits->rnd_nr > 0)
		{
			/* take value from base header */
			decoded->rnd = bits->rnd;
		}
		else if(new_inner_ip_hdr)
		{
			rohc_decomp_warn(context, "failed to decode inner IP header: no "
			                 "information in context and no RND bit in packet");
			goto error;
		}
		else
		{
			/* keep context value */
			decoded->rnd = ctxt->rnd;
		}
		rohc_decomp_debug(context, "decoded %s RND = %d", descr, decoded->rnd);

		/* SID flag */
		if(bits->sid_nr > 0)
		{
			/* take value from base header */
			decoded->sid = bits->sid;
		}
		else if(new_inner_ip_hdr)
		{
			rohc_decomp_warn(context, "failed to decode inner IP header: no "
			                 "information in context and no SID bit in packet");
			goto error;
		}
		else
		{
			/* keep context value */
			decoded->sid = ctxt->sid;
		}
		rohc_decomp_debug(context, "decoded %s SID = %d", descr, decoded->sid);

		/* IP-ID */
		if(!bits->is_id_enc)
		{
			/* IR/IR-DYN packets transmit the IP-ID verbatim, so convert to
			 * host byte order only if nbo=1 */
			if(bits->id_nr != 16)
			{
				rohc_decomp_warn(context, "%s IP-ID is not encoded, but the packet "
				                 "does not provide 16 bits (only %zu bits provided)",
				                 descr, bits->id_nr);
				goto error;
			}
			decoded->id = bits->id;
			if(bits->nbo)
			{
				decoded->id = rohc_ntoh16(bits->id);
			}
			else
			{
#if WORDS_BIGENDIAN == 1
				decoded->id = swab16(bits->id);
#else
				decoded->id = bits->id;
#endif
			}
		}
		else if(decoded->rnd)
		{
			/* take packet value unchanged if random */
			if(decoded->sid)
			{
				rohc_decomp_warn(context, "%s IP-ID got both RND and SID flags!",
				                 descr);
				goto error;
			}
			if(bits->id_nr != 16)
			{
				rohc_decomp_warn(context, "%s IP-ID is random, but the packet does "
				                 "not provide 16 bits (only %zu bits provided)",
				                 descr, bits->id_nr);
				goto error;
			}
			decoded->id = bits->id;
		}
		else if(new_inner_ip_hdr)
		{
			rohc_decomp_warn(context, "failed to decode inner IP header: no "
			                 "information in context and no IP-ID bit in packet");
			goto error;
		}
		else if(decoded->sid)
		{
			/* the IP-ID of the IPv4 header is constant: retrieve the value
			 * that is stored in the context */
			decoded->id = ipv4_get_id(&ctxt->ip);
		}
		else
		{
			/* the IP-ID of the IPv4 header changed in a predictable way:
			 * decode its new value with the help of the decoded SN and the
			 * least-significant IP-ID bits transmitted in the ROHC header */
			int ret;
			ret = ip_id_offset_decode(ip_id_decode, lsb_ref_type, bits->id, bits->id_nr,
			                          decoded_sn, &decoded->id);
			if(ret != 1)
			{
				rohc_decomp_warn(context, "failed to decode %zu %s IP-ID bits "
				                 "0x%x", bits->id_nr, descr, bits->id);
				goto error;
			}
		}
		rohc_decomp_debug(context, "decoded %s IP-ID = 0x%04x (rnd = %d, "
		                  "nbo = %d, sid = %d, nr bits = %zd, bits = 0x%x)",
		                  descr, decoded->id, decoded->rnd, decoded->nbo,
		                  decoded->sid, bits->id_nr, bits->id);

		/* DF flag */
		if(bits->df_nr > 0)
		{
			/* take value from base header */
			decoded->df = bits->df;
		}
		else if(new_inner_ip_hdr)
		{
			rohc_decomp_warn(context, "failed to decode inner IP header: no "
			                 "information in context and no DF bit in packet");
			goto error;
		}
		else
		{
			/* keep context value */
			decoded->df = ipv4_get_df(&ctxt->ip);
		}
		rohc_decomp_debug(context, "decoded %s DF = %d", descr, decoded->df);

		/* source address */
		if(bits->saddr_nr > 0)
		{
			/* take value from base header */
			assert(bits->saddr_nr == 32);
			memcpy(decoded->saddr, bits->saddr, 4);
		}
		else if(new_inner_ip_hdr)
		{
			rohc_decomp_warn(context, "failed to decode inner IP header: no "
			                 "information in context and no source address bit "
			                 "in packet");
			goto error;
		}
		else
		{
			/* keep context value */
			const uint32_t saddr_ctxt = ipv4_get_saddr(&ctxt->ip);
			memcpy(decoded->saddr, &saddr_ctxt, 4);
		}
		rohc_decomp_debug(context, "decoded %s src address = " IPV4_ADDR_FORMAT,
		                  descr, IPV4_ADDR_RAW(decoded->saddr));

		/* destination address */
		if(bits->daddr_nr > 0)
		{
			/* take value from base header */
			assert(bits->daddr_nr == 32);
			memcpy(decoded->daddr, bits->daddr, 4);
		}
		else if(new_inner_ip_hdr)
		{
			rohc_decomp_warn(context, "failed to decode inner IP header: no "
			                 "information in context and no destination address "
			                 "bit in packet");
			goto error;
		}
		else
		{
			/* keep context value */
			const uint32_t daddr_ctxt = ipv4_get_daddr(&ctxt->ip);
			memcpy(decoded->daddr, &daddr_ctxt, 4);
		}
		rohc_decomp_debug(context, "decoded %s dst address = " IPV4_ADDR_FORMAT,
		                  descr, IPV4_ADDR_RAW(decoded->daddr));
	}

	return true;

error:
	return false;
}


/**
 * @brief Update context with decoded values
 *
 * The following decoded values are updated in context:
 *  - SN
 *  - static & dynamic fields of the outer IP header
 *  - static & dynamic fields of the inner IP header (if it exists)
 *  - fields for the next header (optional, depends on profile)
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context              The decompression context
 * @param decoded              The decoded values to update in the context
 * @param payload_len          The length of the packet payload
 * @param[out] do_change_mode  Whether the profile context wants to change
 *                             its operational mode or not
 */
void rfc3095_decomp_update_ctxt(struct rohc_decomp_ctxt *const context,
                                const struct rohc_decoded_values *const decoded,
                                const size_t payload_len __attribute__((unused)),
                                bool *const do_change_mode)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	bool keep_ref_minus_1; /* for action upon CRC failure */

	/* action upon CRC failure: in case of incorrect SN updates, ref-1 shall not
	 * be replaced by ref0 in the LSB context */
	if(context->crc_corr.algo == ROHC_DECOMP_CRC_CORR_SN_UPDATES &&
	   context->crc_corr.counter == 3)
	{
		/* step f of RFC3095, §5.3.2.2.5. Repair of incorrect SN updates:
		 *   If the decompressed header generated in d. passes the CRC test,
		 *   ref -1 is not changed while ref 0 is set to SN curr2. */
		keep_ref_minus_1 = true;
	}
	else
	{
		/* nominal case and other repair algorithms replace both ref 0 and
		 * ref -1 */
		keep_ref_minus_1 = false;
	}

	/* tell compressor about the current decompressor's operating mode
	 * if they are different */
	if(decoded->mode != context->mode)
	{
		rohc_decomp_debug(context, "mode different in compressor (%d) and "
		                  "decompressor (%d)", decoded->mode, context->mode);
		*do_change_mode = true;
	}
	else
	{
		*do_change_mode = false;
	}

	/* warn if value(SN) is not context(SN) + 1 */
	if(context->num_recv_packets >= 1 && !decoded->is_context_reused)
	{
		uint32_t sn_context;
		uint32_t expected_next_sn;

		/* get context(SN) */
		sn_context = context->profile->get_sn(context);

		/* compute the next SN value we expect in packet */
		/* other profiles handle 16-bit SN values */
		if(sn_context == 0xffff)
		{
			expected_next_sn = 0;
		}
		else
		{
			expected_next_sn = sn_context + 1;
		}

		/* do we decoded the expected SN? */
		if(decoded->sn == sn_context)
		{
			/* same SN: duplicated packet detected! */
			rohc_info(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
			          "packet seems to be a duplicated packet (SN = 0x%x)",
			          sn_context);
			context->nr_lost_packets = 0;
			context->nr_misordered_packets = 0;
			context->is_duplicated = true;
		}
		else if(decoded->sn > expected_next_sn)
		{
			/* bigger SN: some packets were lost or failed to be decompressed */
			rohc_info(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
			          "%u packets seem to have been lost, damaged, or failed "
			          "to be decompressed (SN jumped from 0x%x to 0x%x)",
			          decoded->sn - expected_next_sn, sn_context, decoded->sn);
			context->nr_lost_packets = decoded->sn - expected_next_sn;
			context->nr_misordered_packets = 0;
			context->is_duplicated = false;
		}
		else if(decoded->sn < expected_next_sn)
		{
			/* smaller SN: order was changed on the network channel */
			rohc_info(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
			          "packet seems to come late (SN jumped back from 0x%x to 0x%x)",
			          sn_context, decoded->sn);
			context->nr_lost_packets = 0;
			context->nr_misordered_packets = expected_next_sn - decoded->sn;
			context->is_duplicated = false;
		}
		else
		{
			/* SN is as expected */
			context->nr_lost_packets = 0;
			context->nr_misordered_packets = 0;
			context->is_duplicated = false;
		}
	}
	else
	{
		/* no SN reference to detect SN duplicates or SN jumps */
		context->nr_lost_packets = 0;
		context->nr_misordered_packets = 0;
		context->is_duplicated = false;
	}

	/* update SN */
	rohc_lsb_set_ref(&rfc3095_ctxt->sn_lsb_ctxt, decoded->sn, keep_ref_minus_1);

	/* maybe current packet changed the number of IP headers */
	rfc3095_ctxt->multiple_ip = decoded->multiple_ip;

	/* update fields related to the outer IP header */
	ip_set_version(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.version);
	ip_set_protocol(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.proto);
	ip_set_tos(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.tos);
	ip_set_ttl(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.ttl);
	ip_set_saddr(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.saddr);
	ip_set_daddr(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.daddr);
	if(decoded->outer_ip.version == IPV4)
	{
		ipv4_set_id(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.id);
		ip_id_offset_set_ref(&rfc3095_ctxt->outer_ip_id_offset_ctxt,
		                     decoded->outer_ip.id, decoded->sn, keep_ref_minus_1);
		ipv4_set_df(&rfc3095_ctxt->outer_ip_changes->ip, decoded->outer_ip.df);
		rfc3095_ctxt->outer_ip_changes->nbo = decoded->outer_ip.nbo;
		rfc3095_ctxt->outer_ip_changes->rnd = decoded->outer_ip.rnd;
		rfc3095_ctxt->outer_ip_changes->sid = decoded->outer_ip.sid;
	}

	/* update context with decoded fields for next header if required */
	if(rfc3095_ctxt->update_context != NULL)
	{
		rfc3095_ctxt->update_context(context, decoded);
	}
}


/**
 * @brief Reset the extracted bits for next parsing
 *
 * @param rfc3095_ctxt  The generic decompression context
 * @param[out] bits     The extracted bits to reset
 */
static void reset_extr_bits(const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                            struct rohc_extr_bits *const bits)
{
	assert(rfc3095_ctxt != NULL);
	assert(bits != NULL);

	/* set every bits and sizes to 0 except for CCE-related variables */
	{
		const rohc_tristate_t cfi = bits->cfi;
		memset(bits, 0, sizeof(struct rohc_extr_bits));
		bits->cfi = cfi;
	}

	/* by default, use ref 0 for LSB decoding (ref -1 will be used only for
	 * correction upon CRC failure) */
	bits->lsb_ref_type = ROHC_LSB_REF_0;
	/* by default, do not apply any offset on reference SN (it will be applied
	 * only for correction upon CRC failure) */
	bits->sn_ref_offset = 0;

	/* by default context is not re-used */
	bits->is_context_reused = false;

	/* by default same number of IP headers as in previous packets */
	bits->multiple_ip = rfc3095_ctxt->multiple_ip;

	/* set IP version and NBO/RND flags for outer IP header */
	bits->outer_ip.version = ip_get_version(&rfc3095_ctxt->outer_ip_changes->ip);
	bits->outer_ip.nbo = rfc3095_ctxt->outer_ip_changes->nbo;
	bits->outer_ip.rnd = rfc3095_ctxt->outer_ip_changes->rnd;
	bits->outer_ip.is_id_enc = true;
}

