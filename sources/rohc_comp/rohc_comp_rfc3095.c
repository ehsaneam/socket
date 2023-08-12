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
 * @file   rohc_comp_rfc3095.c
 * @brief  Generic framework for RFC3095-based compression profiles such as
 *         IP-only, UDP, UDP-Lite, ESP, and RTP profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 */

#include "rohc_comp_rfc3095.h"
#include "rohc_traces.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "rohc_bit_ops.h"
#include "cid.h"
#include "ip_id_offset.h"
#include "sdvl.h"
#include "crc.h"

#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "config.h"


/*
 * Definitions of private constants and macros
 */

/** A flag to indicate that IPv4 Type Of Service field changed in IP header */
#define MOD_TOS       0x0001
/** A flag to indicate that IPv4 Time To Live field changed in IP header */
#define MOD_TTL       0x0010
/** A flag to indicate that the IPv4 Protocol field changed in IP header */
#define MOD_PROTOCOL  0x0020
/** A flag to indicate that an errror occurred */
#define MOD_ERROR 0x0008


/*
 * Prototypes of main private functions
 */

static void ip_header_info_new(struct ip_header_info *const header_info,
                               const struct ip_packet *const ip,
                               const size_t list_trans_nr,
                               const size_t wlsb_window_width,
                               rohc_trace_callback2_t trace_cb,
                               void *const trace_cb_priv,
                               const int profile_id)
	__attribute__((nonnull(1, 2)));

static void c_init_tmp_variables(struct generic_tmp_vars *const tmp_vars);

static rohc_packet_t decide_packet(struct rohc_comp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));

static rohc_ext_t decide_extension_uor2(const struct rohc_comp_ctxt *const context,
                                        const size_t nr_innermost_ip_id_bits,
                                        const size_t nr_outermost_ip_id_bits)
	__attribute__((warn_unused_result, nonnull(1)));
static int code_packet(struct rohc_comp_ctxt *const context,
                       const struct net_pkt *const uncomp_pkt,
                       uint8_t *const rohc_pkt,
                       const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct net_pkt *const uncomp_pkt,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int code_IR_DYN_packet(struct rohc_comp_ctxt *const context,
                              const struct net_pkt *const uncomp_pkt,
                              uint8_t *const rohc_pkt,
                              const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rohc_code_static_part(const struct rohc_comp_ctxt *const context,
                                 const struct net_pkt *const uncomp_pkt,
                                 uint8_t *const rohc_pkt,
                                 int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rohc_code_static_ip_part(const struct rohc_comp_ctxt *const context,
                                    struct ip_header_info *const header_info,
                                    const struct ip_packet *const ip,
                                    uint8_t *const dest,
                                    int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static int code_ipv4_static_part(const struct rohc_comp_ctxt *const context,
                                 struct ip_header_info *const header_info,
                                 const struct ip_packet *const ip,
                                 uint8_t *const dest,
                                 int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static int rohc_code_dynamic_part(const struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt,
                                  uint8_t *const rohc_pkt,
                                  int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rohc_code_dynamic_ip_part(const struct rohc_comp_ctxt *const context,
                                     const unsigned int hdr_pos,
                                     struct ip_header_info *const header_info,
                                     const struct ip_packet *const ip,
                                     uint8_t *const dest,
                                     int counter)
	__attribute__((warn_unused_result, nonnull(1, 3, 4, 5)));

static int code_ipv4_dynamic_part(const struct rohc_comp_ctxt *const context,
                                  struct ip_header_info *const header_info,
                                  const struct ip_packet *const ip,
                                  uint8_t *const dest,
                                  int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static int code_uo_remainder(struct rohc_comp_ctxt *const context,
                             const struct net_pkt *const uncomp_pkt,
                             uint8_t *const dest,
                             int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int code_UO0_packet(struct rohc_comp_ctxt *const context,
                           const struct net_pkt *const uncomp_pkt,
                           uint8_t *const rohc_pkt,
                           const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rohc_comp_rfc3095_build_uo1_pkt(struct rohc_comp_ctxt *const context,
                                           const struct net_pkt *const uncomp_pkt,
                                           uint8_t *const rohc_pkt,
                                           const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int code_UO2_packet(struct rohc_comp_ctxt *const context,
                           const struct net_pkt *const uncomp_pkt,
                           uint8_t *const rohc_pkt,
                           const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int code_UOR2_bytes(const struct rohc_comp_ctxt *const context,
                           const rohc_ext_t extension,
                           uint8_t *const f_byte,
                           uint8_t *const s_byte,
                           uint8_t *const t_byte)
	__attribute__((warn_unused_result, nonnull(1, 3, 4, 5)));

static int code_EXT0_packet(const struct rohc_comp_ctxt *const context,
                            uint8_t *const dest,
                            int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int code_EXT1_packet(const struct rohc_comp_ctxt *const context,
                            uint8_t *const dest,
                            int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int code_EXT2_packet(const struct rohc_comp_ctxt *const context,
                            uint8_t *const dest,
                            int counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int code_EXT3_packet(struct rohc_comp_ctxt *const context,
                            const struct net_pkt *const uncomp_pkt,
                            uint8_t *const dest,
                            int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int code_EXT3_nortp_packet(struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt,
                                  uint8_t *const dest,
                                  int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int header_flags(const struct rohc_comp_ctxt *const context,
                        struct ip_header_info *const header_info,
                        const unsigned short changed_f,
                        const struct ip_packet *const ip,
                        const int ip2_or_I2,
                        uint8_t *const dest,
                        int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 6)));

static int header_fields(const struct rohc_comp_ctxt *const context,
                         struct ip_header_info *const header_info,
                         const unsigned short changed_f,
                         const struct ip_packet *ip,
                         const int I,
                         const ip_header_pos_t ip_hdr_pos,
                         uint8_t *const dest,
                         int counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 7)));

static uint8_t compute_uo_crc(struct rohc_comp_ctxt *const context,
                              const struct net_pkt *const uncomp_pkt,
                              const rohc_crc_type_t crc_type,
                              const uint8_t crc_init,
                              const uint8_t *const crc_table)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));

static void update_context(struct rohc_comp_ctxt *const context,
                           const struct net_pkt *const uncomp_pkt)
	__attribute__((nonnull(1, 2)));
static void update_context_ip_hdr(struct ip_header_info *const ip_flags,
                                  const struct ip_packet *const ip)
	__attribute__((nonnull(1, 2)));

static bool rohc_comp_rfc3095_detect_changes(struct rohc_comp_ctxt *const context,
                                             const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static int changed_static_both_hdr(struct rohc_comp_ctxt *const context,
                                   const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static int changed_static_one_hdr(struct rohc_comp_ctxt *const context,
                                  const unsigned short changed_fields,
                                  struct ip_header_info *const header_info)
	__attribute__((warn_unused_result, nonnull(1, 3)));
static int changed_dynamic_both_hdr(struct rohc_comp_ctxt *const context,
                                    const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static int changed_dynamic_one_hdr(struct rohc_comp_ctxt *const context,
                                   const unsigned short changed_fields,
                                   struct ip_header_info *const header_info,
                                   const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));
static unsigned short detect_changed_fields(const struct rohc_comp_ctxt *const context,
                                            struct ip_header_info *const header_info, /* TODO: add const */
                                            const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static bool is_field_changed(const unsigned short changed_fields,
                             const unsigned short check_field)
	__attribute__((warn_unused_result, const));
static void detect_ip_id_behaviours(struct rohc_comp_ctxt *const context,
                                    const struct net_pkt *const uncomp_pkt)
	__attribute__((nonnull(1, 2)));
static void detect_ip_id_behaviour(const struct rohc_comp_ctxt *const context,
                                   struct ip_header_info *const header_info,
                                   const struct ip_packet *const ip)
	__attribute__((nonnull(1, 2, 3)));

static bool encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                 const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void rohc_get_innermost_ipv4_non_rnd(const struct rohc_comp_ctxt *const context,
                                            ip_header_pos_t *const pos,
                                            size_t *const nr_bits,
                                            uint16_t *const offset)
	__attribute__((nonnull(1, 2, 3, 4)));

static void rohc_comp_rfc3095_get_ext3_I_flags(const struct rohc_comp_ctxt *const context,
                                               const struct net_pkt *const uncomp_pkt,
                                               const rohc_packet_t packet_type,
                                               const size_t nr_ip_id_bits,
                                               const size_t nr_ip_id_bits2,
                                               ip_header_pos_t *const innermost_ipv4_non_rnd,
                                               uint8_t *const I,
                                               uint8_t *const I2)
	__attribute__((nonnull(1, 2, 6, 7, 8)));

/*
 * Definitions of public functions
 */


/**
 * @brief Check if a specified IP field has changed.
 *
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param check_field    The field for which to check a change
 * @return               1 if the field changed, 0 if not
 *
 * @see changed_fields
 */
static bool is_field_changed(const unsigned short changed_fields,
                             const unsigned short check_field)
{
	return ((changed_fields & check_field) != 0);
}


/**
 * @brief Initialize the IP header info stored in the context
 *
 * @param header_info        The IP header info to initialize
 * @param ip                 The IP header
 * @param list_trans_nr      The number of uncompressed transmissions for
 *                           list compression (L)
 * @param wlsb_window_width  The width of the W-LSB sliding window for IPv4
 *                           IP-ID (must be > 0)
 * @param trace_cb           The function to call for printing traces
 * @param trace_cb_priv      An optional private context, may be NULL
 * @param profile_id         The ID of the associated compression profile
 */
static void ip_header_info_new(struct ip_header_info *const header_info,
                               const struct ip_packet *const ip,
                               const size_t list_trans_nr,
                               const size_t wlsb_window_width,
                               rohc_trace_callback2_t trace_cb,
                               void *const trace_cb_priv,
                               const int profile_id)
{
	assert(profile_id>=0);
	assert(trace_cb==NULL || trace_cb!=NULL);
	assert(trace_cb_priv==NULL || trace_cb_priv!=NULL);
	assert(header_info != NULL);
	assert(ip != NULL);
	assert(list_trans_nr > 0);
	assert(wlsb_window_width > 0);

	/* store the IP version in the header info */
	header_info->version = ip_get_version(ip);

	/* we haven't seen any header so far */
	header_info->is_first_header = true;

	/* version specific initialization */
	if(header_info->version == IPV4)
	{
		/* init the parameters to encode the IP-ID with W-LSB encoding */
		wlsb_init(&header_info->info.v4.ip_id_window, 16, wlsb_window_width,
		          ROHC_LSB_SHIFT_IP_ID);

		/* init the thresholds the counters must reach before launching
		 * an action */
		header_info->tos_count = MAX_FO_COUNT;
		header_info->ttl_count = MAX_FO_COUNT;
		header_info->info.v4.df_count = MAX_FO_COUNT;
		header_info->protocol_count = MAX_FO_COUNT;
		header_info->info.v4.rnd_count = MAX_FO_COUNT;
		header_info->info.v4.nbo_count = MAX_FO_COUNT;
		header_info->info.v4.sid_count = MAX_FO_COUNT;
	}
}

/**
 * @brief Initialize all temporary variables stored in the context.
 *
 * @param tmp_vars  The temporary variables to initialize
 */
static void c_init_tmp_variables(struct generic_tmp_vars *const tmp_vars)
{
	tmp_vars->changed_fields = MOD_ERROR;
	tmp_vars->changed_fields2 = MOD_ERROR;
	tmp_vars->send_static = -1;
	tmp_vars->send_dynamic = -1;

	/* do not send any bits of SN, outer/inner IP-IDs, outer/inner IPv6
	 * extension header list by default */
	tmp_vars->nr_sn_bits_less_equal_than_4 = 0;
	tmp_vars->nr_sn_bits_more_than_4 = 0;
	tmp_vars->nr_ip_id_bits = 0;
	tmp_vars->nr_ip_id_bits2 = 0;

	tmp_vars->packet_type = ROHC_PACKET_UNKNOWN;
}


/**
 * @brief Create a new context and initialize it thanks to the given IP packet.
 *
 * @param context     The compression context
 * @param sn_bits_nr  The maximum number of bits used for SN
 * @param sn_shift    The shift parameter (p) to use for encoding SN with W-LSB
 * @param packet      The packet given to initialize the new context
 * @return            true if successful, false otherwise
 */
bool rohc_comp_rfc3095_create(struct rohc_comp_ctxt *const context,
                              const size_t sn_bits_nr,
                              const rohc_lsb_shift_t sn_shift,
                              const struct net_pkt *const packet)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	assert(context != NULL);
	assert(context->profile != NULL);
	assert(packet != NULL);

	rohc_comp_debug(context, "new generic context required for a new stream");

	/* allocate memory for the generic part of the context */
	rfc3095_ctxt = calloc(1, sizeof(struct rohc_comp_rfc3095_ctxt));
	if(rfc3095_ctxt == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for generic part of the profile context");
		goto quit;
	}
	context->specific = rfc3095_ctxt;

	/* initialize some context variables:
	 *  1. init the parameters to encode the SN with W-LSB encoding
	 *  2. init the info related to the outer IP header, the info related to the
	 *     inner IP header will be initialized later if necessary
	 *  3. init the temporary variables
	 *  4. init the profile-specific variables to safe values
	 */

	/* step 1 */
	rohc_comp_debug(context, "use shift parameter %d for LSB-encoding of the "
	                "%zu-bit SN", sn_shift, sn_bits_nr);
	wlsb_init(&rfc3095_ctxt->sn_window, sn_bits_nr,
	          context->compressor->wlsb_window_width, sn_shift);
	wlsb_init(&rfc3095_ctxt->msn_non_acked, 16,
	          context->compressor->wlsb_window_width, sn_shift);

	/* step 3 */
	ip_header_info_new(&rfc3095_ctxt->outer_ip_flags,
	                   &packet->outer_ip,
	                   context->compressor->list_trans_nr,
	                   context->compressor->wlsb_window_width,
	                   context->compressor->trace_callback,
	                   context->compressor->trace_callback_priv,
	                   context->profile->id);
	if(packet->ip_hdr_nr > 1)
	{
		ip_header_info_new(&rfc3095_ctxt->inner_ip_flags,
		                   &packet->inner_ip,
		                   context->compressor->list_trans_nr,
		                   context->compressor->wlsb_window_width,
		                   context->compressor->trace_callback,
		                   context->compressor->trace_callback_priv,
		                   context->profile->id);
		rfc3095_ctxt->ip_hdr_nr = 2;
	}
	else
	{
		rfc3095_ctxt->ip_hdr_nr = 1;
	}

	/* step 4 */
	c_init_tmp_variables(&rfc3095_ctxt->tmp);

	/* step 5 */
	rfc3095_ctxt->specific = NULL;
	rfc3095_ctxt->next_header_proto = packet->transport->proto;
	rfc3095_ctxt->next_header_len = 0;
	rfc3095_ctxt->decide_state = rohc_comp_rfc3095_decide_state;
	rfc3095_ctxt->decide_FO_packet = NULL;
	rfc3095_ctxt->decide_SO_packet = NULL;
	rfc3095_ctxt->decide_extension = NULL;
	rfc3095_ctxt->init_at_IR = NULL;
	rfc3095_ctxt->get_next_sn = NULL;
	rfc3095_ctxt->code_static_part = NULL;
	rfc3095_ctxt->code_dynamic_part = NULL;
	rfc3095_ctxt->code_UO_packet_head = NULL;
	rfc3095_ctxt->code_uo_remainder = NULL;
	rfc3095_ctxt->compute_crc_static = compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = compute_crc_dynamic;

	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	return true;

quit:
	return false;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void rohc_comp_rfc3095_destroy(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;

	zfree(rfc3095_ctxt->specific);
	free(rfc3095_ctxt);
}


/**
 * @brief Check if the given packet corresponds to an IP-based profile
 *
 * Conditions are:
 *  \li the version of the outer IP header is 4 or 6
 *  \li if the outer IP header is IPv4, it does not contain options
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers and if the inner IP header is IPv4,
 *      it does not contain options
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp    The ROHC compressor
 * @param packet  The packet to check
 * @return        Whether the IP packet corresponds to the profile:
 *                  \li true if the IP packet corresponds to the profile,
 *                  \li false if the IP packet does not correspond to
 *                      the profile
 */
bool rohc_comp_rfc3095_check_profile(const struct rohc_comp *const comp,
                                     const struct net_pkt *const packet)
{
	ip_version version;

	assert(comp != NULL);
	assert(packet != NULL);

	/* check the IP version of the outer header */
	version = ip_get_version(&packet->outer_ip);
	if(version != IPV4)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "the outer IP packet (type = %d) is not supported by the "
		           "profile: only IPv%d is supported",
		           version, IPV4);
		goto bad_profile;
	}

	/* if outer header is IPv4, check the presence of options */
	if(version == IPV4 &&
	   ipv4_get_hdrlen(&packet->outer_ip) != sizeof(struct ipv4_hdr))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "the outer IPv4 packet is not supported by the profile: "
		           "IP options are not accepted");
		goto bad_profile;
	}

	/* check if the outer header is a fragment */
	if(ip_is_fragment(&packet->outer_ip))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "the outer IP packet is fragmented");
		goto bad_profile;
	}

	/* check if the checksum of the outer IP header is correct */
	if(packet->outer_ip.version == IPV4 &&
	   (comp->features & ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == 0 &&
	   ip_fast_csum(packet->outer_ip.data,
	                sizeof(struct ipv4_hdr) / sizeof(uint32_t)) != 0)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "the outer IP packet is not correct (bad checksum)");
		goto bad_profile;
	}

	/* check the inner IP header if there is one */
	if(packet->ip_hdr_nr > 1)
	{
		/* check the IP version of the inner header */
		version = ip_get_version(&packet->inner_ip);
		if(version != IPV4)
		{
			if(packet->inner_ip.size > 0)
			{
				const uint8_t pkt_vers = (packet->inner_ip.data[0] >> 4) & 0x0f;
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "the inner IP packet contains a bad version (%u): only "
				           "IPv%d is supported", pkt_vers, IPV4);
			}
			else
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "the inner IP packet contains a bad version: only "
				           "IPv%d is supported", IPV4);
			}
			goto bad_profile;
		}

		/* if inner header is IPv4, check the presence of options */
		if(version == IPV4 &&
		   ipv4_get_hdrlen(&packet->inner_ip) != sizeof(struct ipv4_hdr))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "the inner IPv4 packet is not supported by the profile: "
			           "IP options are not accepted");
			goto bad_profile;
		}

		/* check if the inner header is a fragment */
		if(ip_is_fragment(&packet->inner_ip))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "the inner IP packet is fragmented");
			goto bad_profile;
		}

		/* check if the checksum of the inner IP header is correct */
		if(packet->inner_ip.version == IPV4 &&
		   (comp->features & ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == 0 &&
		   ip_fast_csum(packet->inner_ip.data,
		                sizeof(struct ipv4_hdr) / sizeof(uint32_t)) != 0)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "the inner IP packet is not correct (bad checksum)");
			goto bad_profile;
		}
	}

	return true;

bad_profile:
	return false;
}


/**
 * @brief Encode an IP packet according to a pattern decided by several
 *        different factors.
 *
 * 1. parse uncompressed packet (done in \ref rohc_compress4)\n
 * 2. detect changes between the new uncompressed packet and the context\n
 * 3. decide new compressor state\n
 * 4. determine how many bytes are required for every field\n
 * 5. decide which packet to send\n
 * 6. code the ROHC header\n
 * 7. copy the packet payload (done in \ref rohc_compress4)\n
 * 8. update the context with the new headers\n
 * \n
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
int rohc_comp_rfc3095_encode(struct rohc_comp_ctxt *const context,
                             const struct net_pkt *const uncomp_pkt,
                             uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len,
                             rohc_packet_t *const packet_type,
                             size_t *const payload_offset)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	rfc3095_ctxt->tmp.changed_fields2 = 0;
	rfc3095_ctxt->tmp.nr_ip_id_bits2 = 0;
	rfc3095_ctxt->tmp.packet_type = ROHC_PACKET_UNKNOWN;

	/* detect changes between new uncompressed packet and context */
	if(!rohc_comp_rfc3095_detect_changes(context, uncomp_pkt))
	{
		rohc_comp_warn(context, "failed to detect changes in uncompressed packet");
		goto error;
	}

	/* decide in which state to go */
	assert(rfc3095_ctxt->decide_state != NULL);
	rfc3095_ctxt->decide_state(context);
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context, uncomp_pkt->time);
	}

	/* compute how many bits are needed to send header fields */
	if(!encode_uncomp_fields(context, uncomp_pkt))
	{
		rohc_comp_warn(context, "failed to compute how many bits are needed "
		               "to send header fields");
		goto error;
	}

	/* decide which packet to send */
	rfc3095_ctxt->tmp.packet_type = decide_packet(context);

	/* does the packet update the decompressor context? */
	if(rohc_packet_carry_crc_7_or_8(rfc3095_ctxt->tmp.packet_type))
	{
		rfc3095_ctxt->msn_of_last_ctxt_updating_pkt = rfc3095_ctxt->sn;
	}

	/* code the ROHC header (and the extension if needed) */
	size = code_packet(context, uncomp_pkt, rohc_pkt, rohc_pkt_max_len);
	if(size < 0)
	{
		goto error;
	}
	/* determine the offset of the payload */
	*payload_offset = net_pkt_get_payload_offset(uncomp_pkt);
	*payload_offset += rfc3095_ctxt->next_header_len;

	/* update the context with the new headers */
	update_context(context, uncomp_pkt);

	/* return the packet type */
	*packet_type = rfc3095_ctxt->tmp.packet_type;

	/* return the length of the ROHC packet */
	return size;

error:
	return -1;
}

/**
 * @brief Detect changes between packet and context
 *
 * @param context     The compression context to compare
 * @param uncomp_pkt  The uncompressed packet to compare
 * @return            true if changes were successfully detected,
 *                    false if a problem occurred
 */
static bool rohc_comp_rfc3095_detect_changes(struct rohc_comp_ctxt *const context,
                                             const struct net_pkt *const uncomp_pkt)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* compute or find the new SN */
	assert(rfc3095_ctxt->get_next_sn != NULL);
	rfc3095_ctxt->sn = rfc3095_ctxt->get_next_sn(context, uncomp_pkt);
	rohc_comp_debug(context, "SN = %u", rfc3095_ctxt->sn);

	/* init or free the context of the inner IP header if the number of IP
	 * headers changed */
	if(uncomp_pkt->ip_hdr_nr != rfc3095_ctxt->ip_hdr_nr)
	{
		if(uncomp_pkt->ip_hdr_nr > 1)
		{
			rohc_comp_debug(context, "packet got one more IP header than context");
			ip_header_info_new(&rfc3095_ctxt->inner_ip_flags,
			                   &uncomp_pkt->inner_ip,
			                   context->compressor->list_trans_nr,
			                   context->compressor->wlsb_window_width,
			                   context->compressor->trace_callback,
			                   context->compressor->trace_callback_priv,
			                   context->profile->id);
		}
		else
		{
			rohc_comp_debug(context, "packet got one less IP header than context");
		}
		rfc3095_ctxt->ip_hdr_nr = uncomp_pkt->ip_hdr_nr;
	}

	/* check NBO and RND of the IP-ID of the IP headers (IPv4 only) */
	detect_ip_id_behaviours(context, uncomp_pkt);

	/* find outer IP fields that changed */
	rfc3095_ctxt->tmp.changed_fields =
		detect_changed_fields(context, &rfc3095_ctxt->outer_ip_flags,
		                      &uncomp_pkt->outer_ip);
	if(rfc3095_ctxt->tmp.changed_fields & MOD_ERROR)
	{
		rohc_comp_warn(context, "failed to detect changed field in outer IP "
		               "header");
		goto error;
	}

	/* find inner IP fields that changed */
	if(uncomp_pkt->ip_hdr_nr > 1)
	{
		rfc3095_ctxt->tmp.changed_fields2 =
			detect_changed_fields(context, &rfc3095_ctxt->inner_ip_flags,
			                      &uncomp_pkt->inner_ip);
		if(rfc3095_ctxt->tmp.changed_fields2  & MOD_ERROR)
		{
			rohc_comp_warn(context, "failed to detect changed field in inner IP "
			               "header");
			goto error;
		}
	}

	/* how many changed fields are static ones? */
	rfc3095_ctxt->tmp.send_static = changed_static_both_hdr(context, uncomp_pkt);

	/* how many changed fields are dynamic ones? */
	rfc3095_ctxt->tmp.send_dynamic = changed_dynamic_both_hdr(context, uncomp_pkt);
	rohc_comp_debug(context, "send_static = %d, send_dynamic = %d",
	                rfc3095_ctxt->tmp.send_static, rfc3095_ctxt->tmp.send_dynamic);

	return true;

error:
	return false;
}


/**
 * @brief Decide the state that should be used for the next packet.
 *
 * The three states are:\n
 *  - Initialization and Refresh (IR),\n
 *  - First Order (FO),\n
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
void rohc_comp_rfc3095_decide_state(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	rohc_comp_state_t curr_state;
	rohc_comp_state_t next_state;

	curr_state = context->state;
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	if(curr_state == ROHC_COMP_STATE_IR)
	{
		if(context->ir_count < MAX_IR_COUNT)
		{
			rohc_comp_debug(context, "no enough packets transmitted in IR state "
			                "for the moment (%zu/%u), so stay in IR state",
			                context->ir_count, MAX_IR_COUNT);
			next_state = ROHC_COMP_STATE_IR;
		}
		else if(rfc3095_ctxt->tmp.send_static)
		{
			rohc_comp_debug(context, "%d STATIC fields changed now or in the "
			                "last few packets, so stay in IR state",
			                rfc3095_ctxt->tmp.send_static);
			next_state = ROHC_COMP_STATE_IR;
		}
		else if(rfc3095_ctxt->tmp.send_dynamic)
		{
			rohc_comp_debug(context, "no STATIC field changed, but %d DYNAMIC "
			                "fields changed now or in the last few packets, so "
			                "go to FO state", rfc3095_ctxt->tmp.send_dynamic);
			next_state = ROHC_COMP_STATE_FO;
		}
		else if((rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
		         rfc3095_ctxt->outer_ip_flags.info.v4.sid_count < MAX_FO_COUNT) ||
		        (rfc3095_ctxt->ip_hdr_nr > 1 &&
		         rfc3095_ctxt->inner_ip_flags.version == IPV4 &&
		         rfc3095_ctxt->inner_ip_flags.info.v4.sid_count < MAX_FO_COUNT))
		{
			rohc_comp_debug(context, "at least one SID flag changed now or in the "
			                "last few packets, so go to FO state");
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			rohc_comp_debug(context, "no STATIC nor DYNAMIC field changed in "
			                "the last few packets, so go to SO state");
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_FO)
	{
		if(context->fo_count < MAX_FO_COUNT)
		{
			rohc_comp_debug(context, "no enough packets transmitted in FO state "
			                "for the moment (%zu/%u), so stay in FO state",
			                context->fo_count, MAX_FO_COUNT);
			next_state = ROHC_COMP_STATE_FO;
		}
		else if(rfc3095_ctxt->tmp.send_static || rfc3095_ctxt->tmp.send_dynamic)
		{
			rohc_comp_debug(context, "%d STATIC and %d DYNAMIC fields changed "
			                "now or in the last few packets, so stay in FO "
			                "state", rfc3095_ctxt->tmp.send_static,
			                rfc3095_ctxt->tmp.send_dynamic);
			next_state = ROHC_COMP_STATE_FO;
		}
		else if((rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
		         rfc3095_ctxt->outer_ip_flags.info.v4.sid_count < MAX_FO_COUNT) ||
		        (rfc3095_ctxt->ip_hdr_nr > 1 &&
		         rfc3095_ctxt->inner_ip_flags.version == IPV4 &&
		         rfc3095_ctxt->inner_ip_flags.info.v4.sid_count < MAX_FO_COUNT))
		{
			rohc_comp_debug(context, "at least one SID flag changed now or in "
			                "the last few packets, so stay in FO state");
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			rohc_comp_debug(context, "no STATIC nor DYNAMIC field changed in "
			                "the last few packets, so go to SO state");
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_SO)
	{
		if(rfc3095_ctxt->tmp.send_static || rfc3095_ctxt->tmp.send_dynamic)
		{
			rohc_comp_debug(context, "%d STATIC and %d DYNAMIC fields changed "
			                "now or in the last few packets, so go back to FO "
			                "state", rfc3095_ctxt->tmp.send_static,
			                rfc3095_ctxt->tmp.send_dynamic);
			next_state = ROHC_COMP_STATE_FO;
		}
		else if((rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
		         rfc3095_ctxt->outer_ip_flags.info.v4.sid_count < MAX_FO_COUNT) ||
		        (rfc3095_ctxt->ip_hdr_nr > 1 &&
		         rfc3095_ctxt->inner_ip_flags.version == IPV4 &&
		         rfc3095_ctxt->inner_ip_flags.info.v4.sid_count < MAX_FO_COUNT))
		{
			rohc_comp_debug(context, "at least one SID flag changed now or in "
			                "the last few packets, so go back to FO state");
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			rohc_comp_debug(context, "no STATIC nor DYNAMIC field changed in "
			                "the last few packets, so stay in SO state");
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else
	{
		rohc_comp_warn(context, "unexpected compressor state %d", curr_state);
		assert(0);
		return;
	}

	rohc_comp_change_state(context, next_state);
}


/**
 * @brief Decide which packet to send when in the different states.
 *
 * In IR state, IR packets are used. In FO and SO, the profile-specific
 * functions are called if they are defined, otherwise IR packets are used.
 *
 * @param context     The compression context
 * @return            \li The packet type among ROHC_PACKET_IR,
 *                        ROHC_PACKET_IR_DYN, ROHC_PACKET_UO_0,
 *                        ROHC_PACKET_UO_1* and ROHC_PACKET_UOR_2*
 *                        in case of success
 *                    \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t decide_packet(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	rohc_packet_t packet;

	switch(context->state)
	{
		case ROHC_COMP_STATE_IR:
		{
			rohc_comp_debug(context, "decide packet in IR state");
			context->ir_count++;
			packet = ROHC_PACKET_IR;
			break;
		}

		case ROHC_COMP_STATE_FO:
		{
			rohc_comp_debug(context, "decide packet in FO state");
			context->fo_count++;
			if(rfc3095_ctxt->decide_FO_packet != NULL)
			{
				packet = rfc3095_ctxt->decide_FO_packet(context);
			}
			else
			{
				packet = ROHC_PACKET_IR;
			}
			break;
		}

		case ROHC_COMP_STATE_SO:
		{
			rohc_comp_debug(context, "decide packet in SO state");
			context->so_count++;
			if(rfc3095_ctxt->decide_SO_packet != NULL)
			{
				packet = rfc3095_ctxt->decide_SO_packet(context);
			}
			else
			{
				packet = ROHC_PACKET_IR;
			}
			break;
		}

		case ROHC_COMP_STATE_UNKNOWN:
		default:
		{
			/* impossible value */
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error,
			            "unknown state (%d), cannot determine packet type",
			            context->state);
		}
	}
	rohc_comp_debug(context, "packet '%s' chosen", rohc_get_packet_descr(packet));

	return packet;

error:
	return ROHC_PACKET_UNKNOWN;
}


/**
 * @brief Build the ROHC packet to send.
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
int code_packet(struct rohc_comp_ctxt *const context,
                const struct net_pkt *const uncomp_pkt,
                uint8_t *const rohc_pkt,
                const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	int (*code_packet_type)(struct rohc_comp_ctxt *const _context,
	                        const struct net_pkt *const _uncomp_pkt,
	                        uint8_t *const _rohc_pkt,
	                        const size_t _rohc_pkt_max_len)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	switch(rfc3095_ctxt->tmp.packet_type)
	{
		case ROHC_PACKET_IR:
			code_packet_type = code_IR_packet;
			break;

		case ROHC_PACKET_IR_DYN:
			code_packet_type = code_IR_DYN_packet;
			break;

		case ROHC_PACKET_UO_0:
			code_packet_type = code_UO0_packet;
			break;

		case ROHC_PACKET_UO_1:
			code_packet_type = rohc_comp_rfc3095_build_uo1_pkt;
			break;

		case ROHC_PACKET_UOR_2:
			code_packet_type = code_UO2_packet;
			break;

		default:
			rohc_comp_debug(context, "unknown packet, failure");
			assert(0); /* should not happen */
			goto error;
	}

	return code_packet_type(context, uncomp_pkt, rohc_pkt, rohc_pkt_max_len);

error:
	return -1;
}


/**
 * @brief Build the IR packet.
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
 8  |             SN                |  2 octets if not RTP nor ESP
    +---+---+---+---+---+---+---+---+
    |                               |
    |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct net_pkt *const uncomp_pkt,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	const size_t nr_of_ip_hdr = uncomp_pkt->ip_hdr_nr;
	uint8_t type;
	size_t counter;
	size_t first_position;
	int crc_position;
	int ret;

	assert(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 16);
	assert((ip_get_version(&uncomp_pkt->outer_ip) == IPV4 &&
	        rfc3095_ctxt->tmp.nr_ip_id_bits <= 16) ||
	       (ip_get_version(&uncomp_pkt->outer_ip) != IPV4 &&
	        rfc3095_ctxt->tmp.nr_ip_id_bits == 0));
	assert((nr_of_ip_hdr == 1 && rfc3095_ctxt->tmp.nr_ip_id_bits2 == 0) ||
	       (nr_of_ip_hdr == 2 &&
	        ip_get_version(&uncomp_pkt->inner_ip) == IPV4 &&
	        rfc3095_ctxt->tmp.nr_ip_id_bits2 <= 16) ||
	       (nr_of_ip_hdr == 2 && ip_get_version(&uncomp_pkt->inner_ip) != IPV4 &&
	        rfc3095_ctxt->tmp.nr_ip_id_bits2 == 0));

	rohc_comp_debug(context, "code IR packet (CID = %zu)", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* initialize some profile-specific things when building an IR
	 * or IR-DYN packet */
	if(rfc3095_ctxt->init_at_IR != NULL)
	{
		rfc3095_ctxt->init_at_IR(context, uncomp_pkt->transport->data);
	}

	/* part 2: type of packet and D flag if dynamic part is included */
	type = 0xfc;
	type &= 0xfe;
	rohc_comp_debug(context, "type of packet = 0x%02x", type);
	rohc_pkt[first_position] = type;

	/* is ROHC buffer large enough for parts 4 and 5 ? */
	if((rohc_pkt_max_len - counter) < 2)
	{
		rohc_comp_warn(context, "ROHC packet is too small for profile ID and "
		               "CRC bytes");
		goto error;
	}

	/* part 4 */
	rohc_comp_debug(context, "profile ID = 0x%02x", context->profile->id);
	rohc_pkt[counter] = context->profile->id;
	counter++;

	/* part 5: the CRC is computed later since it must be computed
	 * over the whole packet with an empty CRC field */
	rohc_comp_debug(context, "CRC = 0x00 for CRC calculation");
	crc_position = counter;
	rohc_pkt[counter] = 0;
	counter++;

	/* part 6: static part */
	ret = rohc_code_static_part(context, uncomp_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		goto error;
	}
	counter = ret;

	/* part 7: if we do not want dynamic part in IR packet, we should not
	 * send the following */
	ret = rohc_code_dynamic_part(context, uncomp_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		goto error;
	}
	counter = ret;

	/* part 8: IR remainder header */
	if(rfc3095_ctxt->code_ir_remainder != NULL)
	{
		ret = rfc3095_ctxt->code_ir_remainder(context, rohc_pkt, rohc_pkt_max_len,
		                                      counter);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to code IR remainder");
			goto error;
		}
		counter = ret;
	}

	/* part 5 */
	rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt, counter,
	                                       CRC_INIT_8,
	                                       context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC (header length = %zu, crc = 0x%x)",
	                counter, rohc_pkt[crc_position]);

	/* invalid CRC-STATIC cache since some STATIC fields may have changed */
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	return counter;

error:
	return -1;
}


/**
 * @brief Build the IR-DYN packet.
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
 7  |             SN                | 2 octets if not RTP nor ESP
    +---+---+---+---+---+---+---+---+
    :                               :
    /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_IR_DYN_packet(struct rohc_comp_ctxt *const context,
                              const struct net_pkt *const uncomp_pkt,
                              uint8_t *const rohc_pkt,
                              const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	size_t counter;
	size_t first_position;
	int crc_position;
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);
	assert(uncomp_pkt != NULL);
	assert(rohc_pkt != NULL);

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	rohc_comp_debug(context, "code IR-DYN packet (CID = %zu)", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* initialize some profile-specific things when building an IR
	 * or IR-DYN packet */
	if(rfc3095_ctxt->init_at_IR != NULL)
	{
		rfc3095_ctxt->init_at_IR(context, uncomp_pkt->transport->data);
	}

	/* part 2 */
	rohc_pkt[first_position] = 0xf8;

	/* is ROHC buffer large enough for parts 4 and 5 ? */
	if((rohc_pkt_max_len - counter) < 2)
	{
		rohc_comp_warn(context, "ROHC packet is too small for profile ID and "
		               "CRC bytes");
		goto error;
	}

	/* part 4 */
	rohc_pkt[counter] = context->profile->id;
	counter++;

	/* part 5: the CRC is computed later since it must be computed
	 * over the whole packet with an empty CRC field */
	crc_position = counter;
	rohc_pkt[counter] = 0;
	counter++;

	/* part 6: dynamic part of outer and inner IP header and dynamic part
	 * of next header */
	ret = rohc_code_dynamic_part(context, uncomp_pkt, rohc_pkt, counter);
	if(ret < 0)
	{
		goto error;
	}
	counter = ret;

	/* part 7: IR-DYN remainder header */
	if(rfc3095_ctxt->code_ir_remainder != NULL)
	{
		ret = rfc3095_ctxt->code_ir_remainder(context, rohc_pkt, rohc_pkt_max_len,
		                                      counter);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to code IR remainder");
			goto error;
		}
		counter = ret;
	}

	/* part 5 */
	rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt, counter,
	                                       CRC_INIT_8,
	                                       context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC (header length = %zu, crc = 0x%x)",
	                counter, rohc_pkt[crc_position]);

	/* invalid CRC-STATIC cache since some STATIC fields may have changed */
	rfc3095_ctxt->is_crc_static_3_cached_valid = false;
	rfc3095_ctxt->is_crc_static_7_cached_valid = false;

	return counter;

error:
	return -1;
}


/**
 * @brief Build the static part of the IR packet
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @param rohc_pkt    The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int rohc_code_static_part(const struct rohc_comp_ctxt *const context,
                                 const struct net_pkt *const uncomp_pkt,
                                 uint8_t *const rohc_pkt,
                                 int counter)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	int ret;

	/* static part of the outer IP header */
	ret = rohc_code_static_ip_part(context, &rfc3095_ctxt->outer_ip_flags,
	                               &uncomp_pkt->outer_ip, rohc_pkt, counter);
	if(ret < 0)
	{
		goto error;
	}
	counter = ret;

	/* static part of the inner IP header (if any) */
	if(uncomp_pkt->ip_hdr_nr > 1)
	{
		ret = rohc_code_static_ip_part(context, &rfc3095_ctxt->inner_ip_flags,
		                               &uncomp_pkt->inner_ip, rohc_pkt, counter);
		if(ret < 0)
		{
			goto error;
		}
		counter = ret;
	}

	/* static part of the transport header (if any) */
	if(rfc3095_ctxt->code_static_part != NULL &&
	   uncomp_pkt->transport->data != NULL)
	{
		ret = rfc3095_ctxt->code_static_part(context, uncomp_pkt->transport->data,
		                                     rohc_pkt, counter);
		if(ret < 0)
		{
			goto error;
		}
		counter = ret;
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Build the static part of one IP header for the IR packet
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IP header the static part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int rohc_code_static_ip_part(const struct rohc_comp_ctxt *const context,
                                    struct ip_header_info *const header_info,
                                    const struct ip_packet *const ip,
                                    uint8_t *const dest,
                                    int counter)
{
	if(ip_get_version(ip) == IPV4)
	{
		counter = code_ipv4_static_part(context, header_info,
		                                ip, dest, counter);
	}

	return counter;
}


/**
 * @brief Build the IPv4 static part of the IR packet
 *
 * \verbatim

 Static part IPv4 (5.7.7.4):

    +---+---+---+---+---+---+---+---+
 1  |  Version = 4  |       0       |
    +---+---+---+---+---+---+---+---+
 2  |           Protocol            |
    +---+---+---+---+---+---+---+---+
 3  /        Source Address         /   4 octets
    +---+---+---+---+---+---+---+---+
 4  /      Destination Address      /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IPv4 header the static part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int code_ipv4_static_part(const struct rohc_comp_ctxt *const context,
                                 struct ip_header_info *const header_info,
                                 const struct ip_packet *const ip,
                                 uint8_t *const dest,
                                 int counter)
{
	uint8_t protocol;
	uint32_t saddr;
	uint32_t daddr;

	/* part 1 */
	dest[counter] = 0x40;
	rohc_comp_debug(context, "version = 0x40");
	counter++;

	/* part 2 */
	protocol = ip_get_protocol(ip);
	rohc_comp_debug(context, "protocol = 0x%02x", protocol);
	dest[counter] = protocol;
	counter++;
	header_info->protocol_count++;

	/* part 3 */
	saddr = ipv4_get_saddr(ip);
	memcpy(&dest[counter], &saddr, 4);
	rohc_comp_debug(context, "src addr = " IPV4_ADDR_FORMAT,
	                IPV4_ADDR_RAW(dest + counter));
	counter += 4;

	/* part 4 */
	daddr = ipv4_get_daddr(ip);
	memcpy(&dest[counter], &daddr, 4);
	rohc_comp_debug(context, "dst addr = " IPV4_ADDR_FORMAT,
	                IPV4_ADDR_RAW(dest + counter));
	counter += 4;

	return counter;
}

/**
 * @brief Build the dynamic part of the IR and IR-DYN packets
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @param rohc_pkt    The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int rohc_code_dynamic_part(const struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt,
                                  uint8_t *const rohc_pkt,
                                  int counter)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	size_t ip_hdr_pos = 0;
	int ret;

	/* dynamic part of the outer IP header */
	ip_hdr_pos++;
	ret = rohc_code_dynamic_ip_part(context, ip_hdr_pos,
	                                &rfc3095_ctxt->outer_ip_flags,
	                                &uncomp_pkt->outer_ip, rohc_pkt, counter);
	if(ret < 0)
	{
		goto error;
	}
	counter = ret;

	/* dynamic part of the inner IP header (if any) */
	if(uncomp_pkt->ip_hdr_nr > 1)
	{
		ip_hdr_pos++;
		ret = rohc_code_dynamic_ip_part(context, ip_hdr_pos,
		                                &rfc3095_ctxt->inner_ip_flags,
		                                &uncomp_pkt->inner_ip, rohc_pkt,
		                                counter);
		if(ret < 0)
		{
			goto error;
		}
		counter = ret;
	}

	/* static part of the transport header (if any) */
	if(rfc3095_ctxt->code_dynamic_part != NULL &&
	   uncomp_pkt->transport->data != NULL)
	{
		ret = rfc3095_ctxt->code_dynamic_part(context, uncomp_pkt->transport->data,
		                                      rohc_pkt, counter);
		if(ret < 0)
		{
			goto error;
		}
		counter = ret;
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of one IP header for the IR/IR-DYN packets
 *
 * @param context     The compression context
 * @param hdr_pos     The position of the IP header: 1 for the outer header
 *                    or 2 for the inner IP header
 * @param header_info The IP header info stored in the profile
 * @param ip          The IP header the dynamic part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer,
 *                    -1 in case of error
 */
static int rohc_code_dynamic_ip_part(const struct rohc_comp_ctxt *const context,
                                     const unsigned int hdr_pos,
                                     struct ip_header_info *const header_info,
                                     const struct ip_packet *const ip,
                                     uint8_t *const dest,
                                     int counter)
{
	int chert = counter;
	counter = hdr_pos;
	counter = chert;
	if(ip_get_version(ip) == IPV4)
	{
		counter = code_ipv4_dynamic_part(context, header_info,
		                                 ip, dest, counter);
	}

	return counter;
}


/**
 * @brief Build the IPv4 dynamic part of the IR and IR-DYN packets.
 *
 * \verbatim

 Dynamic part IPv4 (5.7.7.4):

    +---+---+---+---+---+---+---+---+
 1  |        Type of Service        |
   +---+---+---+---+---+---+---+---+
 2  |         Time to Live          |
    +---+---+---+---+---+---+---+---+
 3  /        Identification         /   2 octets, sent verbatim
    +---+---+---+---+---+---+---+---+
 4  | DF|RND|NBO|SID|       0       |
    +---+---+---+---+---+---+---+---+
 5  / Generic extension header list /  variable length
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IPv4 header the dynamic part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int code_ipv4_dynamic_part(const struct rohc_comp_ctxt *const context,
                                  struct ip_header_info *const header_info,
                                  const struct ip_packet *const ip,
                                  uint8_t *const dest,
                                  int counter)
{
	unsigned int tos;
	unsigned int ttl;
	unsigned int df;
	uint8_t df_rnd_nbo_sid;
	uint16_t id;

	/* part 1 */
	tos = ip_get_tos(ip);
	dest[counter] = tos;
	rohc_comp_debug(context, "TOS = 0x%02x", dest[counter]);
	counter++;
	header_info->tos_count++;

	/* part 2 */
	ttl = ip_get_ttl(ip);
	dest[counter] = ttl;
	rohc_comp_debug(context, "TTL = 0x%02x", dest[counter]);
	counter++;
	header_info->ttl_count++;

	/* part 3 */
	/* always transmit IP-ID verbatim in IR and IR-DYN as stated by
	 * http://www.ietf.org/mail-archive/web/rohc/current/msg01675.html */
	id = ipv4_get_id(ip);
	memcpy(&dest[counter], &id, 2);
	rohc_comp_debug(context, "IP-ID = 0x%02x 0x%02x", dest[counter],
	                dest[counter + 1]);
	counter += 2;

	/* part 4 */
	df = ipv4_get_df(ip);
	df_rnd_nbo_sid = df << 7;
	if(header_info->info.v4.rnd)
	{
		df_rnd_nbo_sid |= 0x40;
	}
	if(header_info->info.v4.nbo)
	{
		df_rnd_nbo_sid |= 0x20;
	}
	if(header_info->info.v4.sid)
	{
		df_rnd_nbo_sid |= 0x10;
	}
	dest[counter] = df_rnd_nbo_sid;
	rohc_comp_debug(context, "(DF = %u, RND = %u, NBO = %u, SID = %u) = 0x%02x",
	                df & 0x01, header_info->info.v4.rnd, header_info->info.v4.nbo,
	                header_info->info.v4.sid, dest[counter]);
	counter++;

	header_info->info.v4.df_count++;
	header_info->info.v4.rnd_count++;
	header_info->info.v4.nbo_count++;
	header_info->info.v4.sid_count++;

	/* part 5 is not supported for the moment, but the field is mandatory,
	   so add a zero byte */
	dest[counter] = 0x00;
	rohc_comp_debug(context, "Generic extension header list = 0x%02x",
	                dest[counter]);
	counter++;

	return counter;
}

/**
 * @brief Build the tail of the UO packet.
 *
 * \verbatim

 The general format for the UO packets is:

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
 4  /   remainder of base header    /                    |
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
 * Parts 7, 8, 10, 11 and 12 are not supported. Parts 1, 2, 3, 4 and 5 are
 * built in packet-specific functions. Parts 6 and 9 are built in this
 * function. Part 13 is built in profile-specific function.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int code_uo_remainder(struct rohc_comp_ctxt *const context,
                             const struct net_pkt *const uncomp_pkt,
                             uint8_t *const dest,
                             int counter)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	uint16_t id;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* parts 6: only IPv4 */
	if(ip_get_version(&uncomp_pkt->outer_ip) == IPV4 &&
	   rfc3095_ctxt->outer_ip_flags.info.v4.rnd == 1)
	{
		/* do not care of Network Byte Order because IP-ID is random */
		id = ipv4_get_id(&uncomp_pkt->outer_ip);
		memcpy(&dest[counter], &id, 2);
		rohc_comp_debug(context, "outer IP-ID = 0x%04x", id);
		counter += 2;
	}

	/* parts 7 and 8 are not supported */

	/* step 9: only IPv4 */
	if(uncomp_pkt->ip_hdr_nr > 1 &&
	   ip_get_version(&uncomp_pkt->inner_ip) == IPV4 &&
	   rfc3095_ctxt->inner_ip_flags.info.v4.rnd == 1)
	{
		/* do not care of Network Byte Order because IP-ID is random */
		id = ipv4_get_id(&uncomp_pkt->inner_ip);
		memcpy(&dest[counter], &id, 2);
		rohc_comp_debug(context, "inner IP-ID = 0x%04x", id);
		counter += 2;
	}

	/* parts 10, 11 and 12 are not supported */

	/* part 13 */
	/* add fields related to the next header */
	if(rfc3095_ctxt->code_uo_remainder != NULL &&
	   uncomp_pkt->transport->data != NULL)
	{
		counter = rfc3095_ctxt->code_uo_remainder(context, uncomp_pkt->transport->data,
		                                          dest, counter);
	}

	return counter;
}


/**
 * @brief Build the UO-0 packet.
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :
    +---+---+---+---+---+---+---+---+
 2  |   first octet of base header  |
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /
    :                               :
    +---+---+---+---+---+---+---+---+

 UO-0 (5.7.1)

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 0 |      SN       |    CRC    |
    +===+===+===+===+===+===+===+===+

\endverbatim
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_UO0_packet(struct rohc_comp_ctxt *const context,
                           const struct net_pkt *const uncomp_pkt,
                           uint8_t *const rohc_pkt,
                           const size_t rohc_pkt_max_len)
{
	size_t counter;
	size_t first_position;
	uint8_t f_byte;
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	uint8_t crc;
	int ret;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	rohc_comp_debug(context, "code UO-0 packet (CID = %zu)", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* build the UO head if necessary */
	if(rfc3095_ctxt->code_UO_packet_head != NULL && uncomp_pkt->transport->data != NULL)
	{
		counter = rfc3095_ctxt->code_UO_packet_head(context, uncomp_pkt->transport->data,
		                                            rohc_pkt, counter, &first_position);
	}

	/* part 2: SN + CRC
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	assert(rfc3095_ctxt->tmp.nr_sn_bits_less_equal_than_4 <= 4);
	f_byte = (rfc3095_ctxt->sn & 0x0f) << 3;
	crc = compute_uo_crc(context, uncomp_pkt, ROHC_CRC_TYPE_3, CRC_INIT_3,
	                     context->compressor->crc_table_3);
	f_byte |= crc;
	rohc_comp_debug(context, "first byte = 0x%02x (CRC = 0x%x)", f_byte, crc);
	rohc_pkt[first_position] = f_byte;

	/* build the UO tail */
	counter = code_uo_remainder(context, uncomp_pkt, rohc_pkt, counter);

	return counter;

error:
	return -1;
}


/**
 * @brief Build the UO-1 packet for the non-RTP profiles
 *
 * The UO-1 packet type cannot be used if there is no IPv4 header in the context
 * or if value(RND) and value(RND2) are both 1.
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :
    +---+---+---+---+---+---+---+---+
 2  |   first octet of base header  |
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /
    :                               :
    +---+---+---+---+---+---+---+---+

 UO-1 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |         IP-ID         |
    +===+===+===+===+===+===+===+===+
 4  |        SN         |    CRC    |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param[out] rohc_pkt     The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc3095_build_uo1_pkt(struct rohc_comp_ctxt *const context,
                                           const struct net_pkt *const uncomp_pkt,
                                           uint8_t *const rohc_pkt,
                                           const size_t rohc_pkt_max_len)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	size_t counter;
	size_t first_position;
	uint8_t crc;
	int ret;

	/* number of IP-ID bits and IP-ID offset to transmit  */
	ip_header_pos_t innermost_ip_hdr;
	size_t nr_innermost_ip_id_bits;
	uint16_t innermost_ip_id_delta;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	rohc_comp_debug(context, "code UO-1 packet (CID = %zu)", context->cid);

	assert(rfc3095_ctxt->tmp.packet_type == ROHC_PACKET_UO_1);

	/* determine the number of IP-ID bits and the IP-ID offset of the
	 * innermost IPv4 header with non-random IP-ID */
	rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
	                                &nr_innermost_ip_id_bits,
	                                &innermost_ip_id_delta);

	/* RFC 3095, section 5.7.5.1 says:
	 *   When no IPv4 header is present in the static context, or the RND
	 *   flags for all IPv4 headers in the context have been established to be
	 *   1, the packet types R-1-ID, R-1-TS, UO-1-ID, and UO-1-TS MUST NOT be
	 *   used.
	 * (UO-1 for non-RTP profile is similar to UO-1-ID for RTP profiles) */
	rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	            innermost_ip_hdr != ROHC_IP_HDR_NONE, error,
	            "UO-1 packet is for IPv4 only");

	/* RFC 3095, section 5.7.5.1 says:
	 *   While in the transient state in which an RND flag is being
	 *   established, the packet types R-1-ID, R-1-TS, UO-1-ID, and UO-1-TS
	 *   MUST NOT be used.
	 * (UO-1 for non-RTP profile is similar to UO-1-ID for RTP profiles) */
	assert(rfc3095_ctxt->outer_ip_flags.version != IPV4 ||
	       rfc3095_ctxt->outer_ip_flags.info.v4.rnd_count >= MAX_FO_COUNT);
	assert(uncomp_pkt->ip_hdr_nr <= 1 ||
	       rfc3095_ctxt->inner_ip_flags.version != IPV4 ||
	       rfc3095_ctxt->inner_ip_flags.info.v4.rnd_count >= MAX_FO_COUNT);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter' */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* build the UO head if necessary */
	if(rfc3095_ctxt->code_UO_packet_head != NULL && uncomp_pkt->transport->data != NULL)
	{
		counter = rfc3095_ctxt->code_UO_packet_head(context, uncomp_pkt->transport->data,
		                                            rohc_pkt, counter, &first_position);
	}

	/* part 2 */
	rohc_pkt[first_position] = 0x80 | (innermost_ip_id_delta & 0x3f);
	rohc_comp_debug(context, "1 0 + IP-ID = 0x%02x", rohc_pkt[first_position]);

	/* part 4: SN + CRC
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	if((rohc_pkt_max_len - counter) < 1)
	{
		rohc_comp_warn(context, "ROHC packet is too small for SN/CRC byte");
		goto error;
	}
	crc = compute_uo_crc(context, uncomp_pkt, ROHC_CRC_TYPE_3, CRC_INIT_3,
	                     context->compressor->crc_table_3);
	rohc_pkt[counter] = ((rfc3095_ctxt->sn & 0x1f) << 3) | (crc & 0x07);
	rohc_comp_debug(context, "SN (%d) + CRC (%x) = 0x%02x",
	                rfc3095_ctxt->sn, crc, rohc_pkt[counter]);
	counter++;

	/* part 5: no extension */

	/* build the UO tail */
	counter = code_uo_remainder(context, uncomp_pkt, rohc_pkt, counter);

	return counter;

error:
	return -1;
}

/**
 * @brief Build the UO-2 packet.
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :
    +---+---+---+---+---+---+---+---+
 2  |   first octet of base header  |
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /
    :                               :
    +---+---+---+---+---+---+---+---+

 UOR-2 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        SN         |
    +===+===+===+===+===+===+===+===+
 5  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

 UOR-2-RTP (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4  | TS| M |       SN              |
    +---+---+---+---+---+---+---+---+
 5  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

 UOR-2-TS (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4  |T=1| M |          SN           |
    +---+---+---+---+---+---+---+---+
 5  | X |           CRC             |
    +---+---+---+---+---+---+---+---+

 UOR-2-ID (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4  |T=0| M |          SN           |
    +---+---+---+---+---+---+---+---+
 5  | X |           CRC             |
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    :                               :
 6  /           Extension           /
    :                               :
     --- --- --- --- --- --- --- ---

 X: X = 0 indicates that no extension is present;
    X = 1 indicates that an extension is present.

 T: T = 0 indicates format UOR-2-ID;
    T = 1 indicates format UOR-2-TS.

\endverbatim
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_UO2_packet(struct rohc_comp_ctxt *const context,
                           const struct net_pkt *const uncomp_pkt,
                           uint8_t *const rohc_pkt,
                           const size_t rohc_pkt_max_len)
{
	uint8_t f_byte;     /* part 2 */
	uint8_t s_byte = 0; /* part 4 */
	uint8_t t_byte = 0; /* part 5 */
	size_t counter;
	size_t first_position;
	size_t t_byte_position;
	rohc_ext_t extension;
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	rohc_packet_t packet_type;
	int (*code_bytes)(const struct rohc_comp_ctxt *_context,
	                  const rohc_ext_t _extension,
	                  uint8_t *const _f_byte,
	                  uint8_t *const _s_byte,
	                  uint8_t *const _t_byte);
	int ret;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	packet_type = rfc3095_ctxt->tmp.packet_type;

	switch(packet_type)
	{
		case ROHC_PACKET_UOR_2:
			rohc_comp_debug(context, "code UOR-2 packet (CID = %zu)",
			                context->cid);
			code_bytes = code_UOR2_bytes;
			break;
		default:
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)", packet_type);
	}

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - parts 4/5 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* build the UO head if necessary */
	if(rfc3095_ctxt->code_UO_packet_head != NULL && uncomp_pkt->transport->data != NULL)
	{
		counter = rfc3095_ctxt->code_UO_packet_head(context, uncomp_pkt->transport->data,
		                                            rohc_pkt, counter, &first_position);
	}

	/* part 2: to be continued, we need to add the 5 bits of SN */
	f_byte = 0xc0; /* 1 1 0 x x x x x */

	/* part 6: decide which extension to use */
	extension = rfc3095_ctxt->decide_extension(context);
	if(extension == ROHC_EXT_UNKNOWN)
	{
		rohc_comp_warn(context, "failed to determine the extension to code");
		goto error;
	}
	rohc_comp_debug(context, "extension '%s' chosen",
	                rohc_get_ext_descr(extension));

	if(extension == ROHC_EXT_3)
	{
		/* invalid CRC-STATIC cache since some STATIC fields may have changed */
		rfc3095_ctxt->is_crc_static_3_cached_valid = false;
		rfc3095_ctxt->is_crc_static_7_cached_valid = false;
	}

	/* part 5: partially calculate the third byte, then remember the position
	 *         of the third byte, its final value is currently unknown
	 *
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	t_byte = compute_uo_crc(context, uncomp_pkt, ROHC_CRC_TYPE_7, CRC_INIT_7,
	                        context->compressor->crc_table_7);
	t_byte_position = counter;
	counter++;

	/* parts 2, 4, 5: complete the three packet-specific bytes and copy them
	 * in packet */
	if(!code_bytes(context, extension, &f_byte, &s_byte, &t_byte))
	{
		rohc_comp_warn(context, "cannot code some UOR-2-* fields");
		goto error;
	}

	rohc_pkt[first_position] = f_byte;
	rohc_comp_debug(context, "f_byte = 0x%02x", f_byte);
	if(t_byte_position >= rohc_pkt_max_len)
	{
		rohc_comp_warn(context, "ROHC packet is too small for 2nd byte");
		goto error;
	}
	rohc_pkt[t_byte_position] = t_byte;
	rohc_comp_debug(context, "t_byte = 0x%02x", t_byte);

	/* part 6: code extension */
	switch(extension)
	{
		case ROHC_EXT_NONE:
			ret = counter;
			break;
		case ROHC_EXT_0:
			ret = code_EXT0_packet(context, rohc_pkt, counter);
			break;
		case ROHC_EXT_1:
			ret = code_EXT1_packet(context, rohc_pkt, counter);
			break;
		case ROHC_EXT_2:
			ret = code_EXT2_packet(context, rohc_pkt, counter);
			break;
		case ROHC_EXT_3:
			ret = code_EXT3_packet(context, uncomp_pkt, rohc_pkt, counter);
			break;
		case ROHC_EXT_UNKNOWN:
		default:
			rohc_comp_warn(context, "unknown extension (%d)", extension);
			goto error;
	}
	if(ret < 0)
	{
		rohc_comp_warn(context, "cannot build extension");
		goto error;
	}
	counter = ret;

	/* build the UO tail */
	counter = code_uo_remainder(context, uncomp_pkt, rohc_pkt, counter);

	return counter;

error:
	return -1;
}


/**
 * @brief Code some fields of the UOR-2 packet
 *
 * This function is called by code_UO2_packet. It should not be called
 * directly.
 *
 * @see code_UO2_packet
 *
 * \verbatim

 UOR-2 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        SN         |
    +===+===+===+===+===+===+===+===+
 5  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context      The compression context
 * @param extension    The extension that will be appended to the packet
 * @param f_byte       IN/OUT: The first byte of the UOR-2 packet
 * @param s_byte       IN/OUT: Not used by the UOR-2 packet
 * @param t_byte       IN/OUT: The second byte of the UOR-2 packet
 * @return             1 if successful, 0 otherwise
 */
static int code_UOR2_bytes(const struct rohc_comp_ctxt *const context,
                           const rohc_ext_t extension,
                           uint8_t *const f_byte,
                           uint8_t *const s_byte __attribute__((unused)),
                           uint8_t *const t_byte)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	switch(extension)
	{
		case ROHC_EXT_NONE:
		{
			rohc_comp_debug(context, "code UOR-2 packet with no extension");

			/* part 2: SN bits */
			assert(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 5);
			*f_byte |= rfc3095_ctxt->sn & 0x1f;

			/* part 5: set the X bit to 0 */
			*t_byte &= ~0x80;

			break;
		}

		case ROHC_EXT_0:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 0");

			/* part 2 */
			assert(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 8);
			*f_byte |= (rfc3095_ctxt->sn >> 3) & 0x1f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case ROHC_EXT_1:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 1");

			/* part 2 */
			assert(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 8);
			*f_byte |= (rfc3095_ctxt->sn >> 3) & 0x1f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case ROHC_EXT_2:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 2");

			/* part 2 */
			assert(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 8);
			*f_byte |= (rfc3095_ctxt->sn >> 3) & 0x1f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case ROHC_EXT_3:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 3");

			/* part 2: check if the s-field needs to be used */
			if(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 5)
			{
				*f_byte |= rfc3095_ctxt->sn & 0x1f;
			}
			else
			{
				assert(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 13);
				*f_byte |= (rfc3095_ctxt->sn >> 8) & 0x1f;
			}

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case ROHC_EXT_UNKNOWN:
		default:
		{
			rohc_comp_warn(context, "unknown extension (%d)", extension);
			goto error;
		}
	}

	return 1;

error:
	return 0;
}

/**
 * @brief Build the extension 0 of the UO-2 packet.
 *
 * \verbatim

 Extension 0 for non-RTP profiles (5.11.4):

    +---+---+---+---+---+---+---+---+
 1  | 0   0 |    SN     |   IP-ID   |
    +---+---+---+---+---+---+---+---+

 Extension 0 for RTP profile (5.7.5):

    +---+---+---+---+---+---+---+---+
 1  | 0   0 |    SN     |    +T     |
    +---+---+---+---+---+---+---+---+

 if T = 0 -> +T = IP-ID
          -> -T = TS

 if T = 1 -> +T = TS
          -> -T = IP-ID

 no T bit -> +T = -T = TS

\endverbatim
 *
 * @param context  The compression context
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 *                 if successful, -1 otherwise
 */
static int code_EXT0_packet(const struct rohc_comp_ctxt *const context,
                            uint8_t *const dest,
                            int counter)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	uint8_t f_byte;
	rohc_packet_t packet_type;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	packet_type = rfc3095_ctxt->tmp.packet_type;

	/* part 1: extension type + SN */
	f_byte = 0;
	f_byte |= (rfc3095_ctxt->sn & 0x07) << 3;

	/* part 1: IP-ID or TS ? */
	switch(packet_type)
	{
		case ROHC_PACKET_UOR_2:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= innermost_ip_id_delta & 0x07;
			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)", packet_type);
		}
	}

	/* part 1: write the byte in the extension */
	dest[counter] = f_byte;
	counter++;

	return counter;

error:
	return -1;
}


/**
 * @brief Build the extension 1 of the UO-2 packet.
 *
 * \verbatim

 Extension 1 for non-RTP profiles (5.11.4):

    +---+---+---+---+---+---+---+---+
 1  | 0   1 |    SN     |   IP-ID   |
    +---+---+---+---+---+---+---+---+
 2  |             IP-ID             |
    +---+---+---+---+---+---+---+---+

 Extension 1 for RTP profile (5.7.5):

    +---+---+---+---+---+---+---+---+
 1  | 0   1 |    SN     |    +T     |
    +---+---+---+---+---+---+---+---+
 2  |               -T              |
    +---+---+---+---+---+---+---+---+

 if T = 0 -> +T = IP-ID
          -> -T = TS

 if T = 1 -> +T = TS
          -> -T = IP-ID

 no T bit -> +T = -T = TS

\endverbatim
 *
 * @param context  The compression context
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 *                 if successful, -1 otherwise
 */
static int code_EXT1_packet(const struct rohc_comp_ctxt *const context,
                            uint8_t *const dest,
                            int counter)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	rohc_packet_t packet_type;
	uint8_t f_byte;
	uint8_t s_byte;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	packet_type = rfc3095_ctxt->tmp.packet_type;

	/* part 1: extension type + SN */
	f_byte = (rfc3095_ctxt->sn & 0x07) << 3;
	f_byte |= 0x40;

	/* parts 1 & 2: IP-ID or TS ? */
	switch(packet_type)
	{
		case ROHC_PACKET_UOR_2:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= (innermost_ip_id_delta >> 8) & 0x07;
			s_byte = innermost_ip_id_delta & 0xff;
			break;
		}
		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)", packet_type);
		}
	}

	/* write parts 1 & 2 in the packet */
	dest[counter] = f_byte;
	counter++;
	dest[counter] = s_byte;
	counter++;

	return counter;

error:
	return -1;
}


/**
 * @brief Build the extension 2 of the UO-2 packet.
 *
 * \verbatim

 Extension 2 for non-RTP profiles (5.11.4):

    +---+---+---+---+---+---+---+---+
 1  | 1   0 |    SN     |   IP-ID2  |
    +---+---+---+---+---+---+---+---+
 2  |            IP-ID2             |
    +---+---+---+---+---+---+---+---+
 3  |             IP-ID             |
    +---+---+---+---+---+---+---+---+

 IP-ID2 is for outer IP-ID field

 Extension 2 for RTP profile (5.7.5):

    +---+---+---+---+---+---+---+---+
 1  | 1   0 |    SN     |     +T    |
    +---+---+---+---+---+---+---+---+
 2  |               +T              |
    +---+---+---+---+---+---+---+---+
 3  |               -T              |
    +---+---+---+---+---+---+---+---+

 if T = 0 -> +T = IP-ID
          -> -T = TS

 if T = 1 -> +T = TS
          -> -T = IP-ID

 no T bit -> +T = -T = TS

\endverbatim
 *
 * @param context  The compression context
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 *                 if successful, -1 otherwise
 */
static int code_EXT2_packet(const struct rohc_comp_ctxt *const context,
                            uint8_t *const dest,
                            int counter)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	rohc_packet_t packet_type;
	uint8_t f_byte;
	uint8_t s_byte;
	uint8_t t_byte;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	packet_type = rfc3095_ctxt->tmp.packet_type;

	/* part 1: extension type + SN */
	f_byte = (rfc3095_ctxt->sn & 0x07) << 3;
	f_byte |= 0x80;
	rohc_comp_debug(context, "3 bits of SN = 0x%x", rfc3095_ctxt->sn & 0x07);

	/* parts 1, 2 & 3: IP-ID or TS ? */
	switch(packet_type)
	{
		case ROHC_PACKET_UOR_2:
		{
			/* To avoid confusion:
			 *  - IP-ID2 in the header description is related to the outer IP header
			 *    and thus to the rfc3095_ctxt->outer_ip_flags header info,
			 *  - IP-ID in the header description is related to the inner IP header
			 *    and thus to the rfc3095_ctxt->inner_ip_flags header info.
			 */

			/* extension 2 for UOR-2 must contain two IPv4 headers with non-random
			   IP-IDs */
			assert(rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
			       rfc3095_ctxt->outer_ip_flags.info.v4.rnd == 0 &&
			       rfc3095_ctxt->ip_hdr_nr > 1 &&
			       rfc3095_ctxt->inner_ip_flags.version == IPV4 &&
			       rfc3095_ctxt->inner_ip_flags.info.v4.rnd == 0);

			f_byte |= (rfc3095_ctxt->outer_ip_flags.info.v4.id_delta >> 8) & 0x07;
			rohc_comp_debug(context, "3 bits of outer IP-ID = 0x%x",
			                f_byte & 0x07);
			s_byte = rfc3095_ctxt->outer_ip_flags.info.v4.id_delta & 0xff;
			rohc_comp_debug(context, "8 bits of outer IP-ID = 0x%x",
			                s_byte & 0xff);
			t_byte = rfc3095_ctxt->inner_ip_flags.info.v4.id_delta & 0xff;
			rohc_comp_debug(context, "8 bits of inner IP-ID = 0x%x",
			                t_byte & 0xff);
			break;
		}
		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)", packet_type);
		}
	}

	/* write parts 1, 2 & 3 in the packet */
	dest[counter] = f_byte;
	counter++;
	dest[counter] = s_byte;
	counter++;
	dest[counter] = t_byte;
	counter++;
	rohc_comp_debug(context, "extension 2: 0x%02x 0x%02x 0x%02x", f_byte,
	                s_byte, t_byte);

	return counter;

error:
	return -1;
}


/**
 * @brief Build the extension 3 of the UO* packet types
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 *                    if successful, -1 otherwise
 */
static int code_EXT3_packet(struct rohc_comp_ctxt *const context,
                            const struct net_pkt *const uncomp_pkt,
                            uint8_t *const dest,
                            int counter)
{
	return code_EXT3_nortp_packet(context, uncomp_pkt, dest, counter);
}


/**
 * @brief Build the extension 3 of the UO-2 packet.
 *
 * \verbatim

 Extension 3 for non-RTP profiles (5.7.5 & 5.11.4):

       0     1     2     3     4     5     6     7
    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |  1     1  |  S  |   Mode    |  I  | ip  | ip2 |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Inner IP header flags        |     |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 3  |            Outer IP header flags              |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 4  |                      SN                       |  if S = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 5  /            Inner IP header fields             /  variable,
    |                                               |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 6  |                     IP-ID                     |  2 octets, if I = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 7  /            Outer IP header fields             /  variable,
    |                                               |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+

\endverbatim
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 *                    if successful, -1 otherwise
 */
static int code_EXT3_nortp_packet(struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt,
                                  uint8_t *const dest,
                                  int counter)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt; /* TODO: const */
	int nr_of_ip_hdr;
	size_t nr_ip_id_bits;
	size_t nr_ip_id_bits2;
	ip_header_pos_t innermost_ipv4_non_rnd;
	rohc_packet_t packet_type;

	uint8_t flags;
	uint8_t S;
	uint8_t I;
	uint8_t ip;
	uint8_t I2;
	uint8_t ip2;

	const struct ip_packet *inner_ip;
	struct ip_header_info *inner_ip_flags; /* TODO: const */
	unsigned short inner_ip_changed_fields;

	const struct ip_packet *outer_ip;
	struct ip_header_info *outer_ip_flags; /* TODO: const */
	unsigned short outer_ip_changed_fields;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	nr_of_ip_hdr = uncomp_pkt->ip_hdr_nr;
	nr_ip_id_bits = rfc3095_ctxt->tmp.nr_ip_id_bits;
	nr_ip_id_bits2 = rfc3095_ctxt->tmp.nr_ip_id_bits2;
	packet_type = rfc3095_ctxt->tmp.packet_type;

	assert(packet_type == ROHC_PACKET_UOR_2);

	/* determine the innermost IPv4 header with non-random IP-ID, but also the
	 * values of the I and I2 flags for additional non-random IP-ID bits */
	rohc_comp_rfc3095_get_ext3_I_flags(context, uncomp_pkt, packet_type,
	                                   nr_ip_id_bits, nr_ip_id_bits2,
	                                   &innermost_ipv4_non_rnd, &I, &I2);
	if(nr_of_ip_hdr == 1)
	{
		inner_ip = &uncomp_pkt->outer_ip;
		inner_ip_flags = &rfc3095_ctxt->outer_ip_flags;
		inner_ip_changed_fields = rfc3095_ctxt->tmp.changed_fields;
		outer_ip = NULL;
		outer_ip_flags = NULL;
		outer_ip_changed_fields = 0;
	}
	else /* double IP headers */
	{
		inner_ip = &uncomp_pkt->inner_ip;
		inner_ip_flags = &rfc3095_ctxt->inner_ip_flags;
		inner_ip_changed_fields = rfc3095_ctxt->tmp.changed_fields2;
		outer_ip = &uncomp_pkt->outer_ip;
		outer_ip_flags = &rfc3095_ctxt->outer_ip_flags;
		outer_ip_changed_fields = rfc3095_ctxt->tmp.changed_fields;
	}

	/* S bit */
	S = (rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 > 5);

	/* ip2 bit (force ip2=1 if I2=1, otherwise I2 is not sent) */
	if(nr_of_ip_hdr == 1)
	{
		ip2 = 0;
	}
	else
	{
		rohc_comp_debug(context, "check for changed fields in the outer IP header");
		if(I2 ||
		   changed_dynamic_one_hdr(context, outer_ip_changed_fields,
		                           outer_ip_flags, outer_ip) ||
		   changed_static_one_hdr(context, outer_ip_changed_fields, outer_ip_flags))
		{
			ip2 = 1;
		}
		else
		{
			ip2 = 0;
		}
	}

	/* ip bit */
	rohc_comp_debug(context, "check for changed fields in the innermost IP header");
	if(changed_dynamic_one_hdr(context, inner_ip_changed_fields & 0x01FF,
	                           inner_ip_flags, inner_ip) ||
	   changed_static_one_hdr(context, inner_ip_changed_fields, inner_ip_flags))
	{
		ip = 1;
	}
	else
	{
		ip = 0;
	}

	/* part 1: extension type + S bit + Mode bits + I bit + ip bit + ip2 bit */
	flags = 0xc0;
	flags |= (S << 5) & 0x20;
	flags |= (context->mode & 0x3) << 3;
	flags |= (I & 0x01) << 2;
	flags |= (ip & 0x01) << 1;
	flags |= (ip2 & 0x01) << 0;
	rohc_comp_debug(context, "S = %d, Mode = %d, I = %d, ip = %d, ip2 = %d "
	                "=> 0x%02x", S, context->mode & 0x3, I, ip, ip2, flags);
	rohc_comp_debug(context, "I2 = %u, ip2 = %u", I2, ip2);
	dest[counter] = flags;
	counter++;

	/* part 2 */
	if(ip)
	{
		counter = header_flags(context, inner_ip_flags, inner_ip_changed_fields,
		                       inner_ip, ip2, dest, counter);
	}

	/* part 3 */
	if(ip2)
	{
		counter = header_flags(context, outer_ip_flags, outer_ip_changed_fields,
		                       outer_ip, I2, dest, counter);
	}

	/* part 4 */
	if(S)
	{
		dest[counter] = rfc3095_ctxt->sn & 0xff;
		counter++;
	}

	/* part 5 */
	if(ip)
	{
		counter = header_fields(context, inner_ip_flags, inner_ip_changed_fields,
		                        inner_ip, 0, ROHC_IP_HDR_SECOND, dest, counter);
	}

	/* part 6 */
	if(I)
	{
		uint16_t id_encoded;

		/* we have 2 IP headers here, so if the I bit is set, one of them
		 * must be the innermost IPv4 header with non-random IP-ID */
		assert(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST ||
		       innermost_ipv4_non_rnd == ROHC_IP_HDR_SECOND);

		/* always transmit the IP-ID encoded, in Network Byte Order */
		if(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST)
		{
			id_encoded = rohc_hton16(rfc3095_ctxt->outer_ip_flags.info.v4.id_delta);
		}
		else
		{
			id_encoded = rohc_hton16(rfc3095_ctxt->inner_ip_flags.info.v4.id_delta);
		}
		memcpy(&dest[counter], &id_encoded, 2);
		rohc_comp_debug(context, "IP ID of IP header #%u = 0x%02x 0x%02x",
		                innermost_ipv4_non_rnd, dest[counter],
		                dest[counter + 1]);
		counter += 2;
	}

	/* part 7 */
	if(ip2)
	{
		counter = header_fields(context, outer_ip_flags, outer_ip_changed_fields,
		                        outer_ip, I2, ROHC_IP_HDR_FIRST, dest, counter);
	}

	/* no IP extension until list compression */

	return counter;
}

/**
 * @brief Build inner or outer IP header flags.
 *
 * This function is used to code the IP header fields of the extension 3 of
 * the UO-2 packet. The function is called twice (one for inner IP header and
 * one for outer IP header) with different arguments.
 *
 * @see code_EXT3_packet
 *
 * \verbatim

 Header flags for IP and UDP profiles (5.11.4):

 For inner flags:

    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |            Inner IP header flags        |     |  if ip = 1
    | TOS | TTL | DF  | PR  | IPX | NBO | RND | ip2 |  ip2 = 0 if non-RTP
    +-----+-----+-----+-----+-----+-----+-----+-----+

 or for outer flags:

    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Outer IP header flags              |
    | TOS2| TTL2| DF2 | PR2 |IPX2 |NBO2 |RND2 |  I2 |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+

\endverbatim
 *
 * @param context        The compression context
 * @param header_info    The header info stored in the profile
 * @param changed_f      The fields that changed, created by the function
 *                       changed_fields
 * @param ip             One inner or outer IP header
 * @param ip2_or_I2      Whether the ip2 (inner, RTP only) or I2 (outer) flag
 *                       is set or not
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build
 *                       buffer
 * @return               The new position in the rohc-packet-under-build buffer
 *
 * @see changed_fields
 */
static int header_flags(const struct rohc_comp_ctxt *const context,
                        struct ip_header_info *const header_info,
                        const unsigned short changed_f,
                        const struct ip_packet *const ip,
                        const int ip2_or_I2,
                        uint8_t *const dest,
                        int counter)
{
	int flags = 0;

	/* for inner and outer flags (1 & 2) */
	if(is_field_changed(changed_f, MOD_TOS) ||
	   header_info->tos_count < MAX_FO_COUNT)
	{
		flags |= 0x80;
	}
	if(is_field_changed(changed_f, MOD_TTL) ||
	   header_info->ttl_count < MAX_FO_COUNT)
	{
		flags |= 0x40;
	}
	if(is_field_changed(changed_f, MOD_PROTOCOL) ||
	   header_info->protocol_count < MAX_FO_COUNT)
	{
		flags |= 0x10;
	}

	/* DF, NBO, RND and I2 are IPv4 specific flags,
	 * there are always set to 0 for IPv6 */
	if(header_info->version == IPV4)
	{
		int df;

		df = ipv4_get_df(ip);
		header_info->info.v4.df_count++;
		flags |= df << 5;

		header_info->info.v4.nbo_count++;
		flags |= header_info->info.v4.nbo << 2;

		header_info->info.v4.rnd_count++;
		flags |= header_info->info.v4.rnd << 1;
	}

	/* the ip2 flag for inner IP flags if non-RTP profile,
	 * the I2 flag for outer IP flags */
	flags |= ip2_or_I2 & 0x01;

	rohc_comp_debug(context, "IPv%d header flags: TOS = %d, TTL = %d, "
	                "DF = %d, PR = %d, IPX = %d, NBO = %d, RND = %d, "
	                "ip2/I2 = %d", header_info->version, (flags >> 7) & 0x1,
	                (flags >> 6) & 0x1, (flags >> 5) & 0x1, (flags >> 4) & 0x1,
	                (flags >> 3) & 0x1, (flags >> 2) & 0x1, (flags >> 1) & 0x1,
	                flags & 0x1);

	/* for inner and outer flags (1 & 2) */
	dest[counter] = flags;
	counter++;

	return counter;
}


/**
 * @brief Build inner or outer IP header fields.
 *
 * This function is used to code the IP header fields of the extension 3 of
 * the UO-2 packet. The function is called twice (one for inner IP header and
 * one for outer IP header) with different arguments.
 *
 * @see code_EXT3_packet
 *
 * \verbatim

    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |         Type of Service/Traffic Class         |  if TOS = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 2  |         Time to Live/Hop Limit                |  if TTL = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 3  |         Protocol/Next Header                  |  if PR = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 4  /         IP extension headers                  /  variable, if IPX = 1
     ..... ..... ..... ..... ..... ..... ..... .....

 For outer IP-ID:
     ..... ..... ..... ..... ..... ..... ..... .....
 5  |                  IP-ID                        |  2 octets,
     ..... ..... ..... ..... ..... ..... ..... .....    if I2 = 1

\endverbatim
 *
 * Part 4 is not supported.
 *
 * @param context        The compression context
 * @param header_info    The header info stored in the profile
 * @param changed_f      The fields that changed, created by the function
 *                       changed_fields
 * @param ip             One inner or outer IP header
 * @param I              The I flag of the IP header
 * @param ip_hdr_pos     The position of the IP header
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build
 *                       buffer
 * @return               The new position in the rohc-packet-under-build buffer
 *
 * @see changed_fields
 */
static int header_fields(const struct rohc_comp_ctxt *const context,
                         struct ip_header_info *const header_info,
                         const unsigned short changed_f,
                         const struct ip_packet *const ip,
                         const int I,
                         const ip_header_pos_t ip_hdr_pos,
                         uint8_t *const dest,
                         int counter)
{
	/* part 1 */
	if(is_field_changed(changed_f, MOD_TOS) ||
	   header_info->tos_count < MAX_FO_COUNT)
	{
		const unsigned int tos = ip_get_tos(ip);
		rohc_comp_debug(context, "IP TOS/TC of IP header #%u = 0x%02x",
		                ip_hdr_pos, tos);
		header_info->tos_count++;
		dest[counter] = tos;
		counter++;
	}

	/* part 2 */
	if(is_field_changed(changed_f, MOD_TTL) ||
	   header_info->ttl_count < MAX_FO_COUNT)
	{
		const unsigned int ttl = ip_get_ttl(ip);
		rohc_comp_debug(context, "IP TTL/HL of IP header #%u = 0x%02x",
		                ip_hdr_pos, ttl);
		header_info->ttl_count++;
		dest[counter] = ttl;
		counter++;
	}

	/* part 3 */
	if(is_field_changed(changed_f, MOD_PROTOCOL) ||
	   header_info->protocol_count < MAX_FO_COUNT)
	{
		const uint8_t protocol = ip_get_protocol(ip);
		rohc_comp_debug(context, "IP Protocol/Next Header of IP header #%u "
		                "= 0x%02x", ip_hdr_pos, protocol);
		header_info->protocol_count++;
		dest[counter] = protocol;
		counter++;
	}

	/* part 5: only for outer IP header if IPv4 */
	if(ip_hdr_pos == ROHC_IP_HDR_FIRST && I == 1)
	{
		uint16_t id_encoded;

		/* always transmit the IP-ID encoded, in Network Byte Order */
		id_encoded = rohc_hton16(header_info->info.v4.id_delta);
		memcpy(&dest[counter], &id_encoded, 2);
		rohc_comp_debug(context, "IP ID of IP header #%u = 0x%02x 0x%02x",
		                ip_hdr_pos, dest[counter], dest[counter + 1]);
		counter += 2;
	}

	return counter;
}


/**
 * @brief Compute the CRC for a UO* packet
 *
 * @param context     The compression context to update
 * @param uncomp_pkt  The uncompressed packet to encode
 * @param crc_type    The type of CRC to compute
 * @param crc_init    The initial value of the CRC
 * @param crc_table   The table of pre-computed CRC
 * @return            The computed CRC
 */
static uint8_t compute_uo_crc(struct rohc_comp_ctxt *const context,
                              const struct net_pkt *const uncomp_pkt,
                              const rohc_crc_type_t crc_type,
                              const uint8_t crc_init,
                              const uint8_t *const crc_table)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	const uint8_t *outer_ip_hdr;
	const uint8_t *inner_ip_hdr;
	const uint8_t *next_header;
	uint8_t crc = crc_init;

	outer_ip_hdr = ip_get_raw_data(&uncomp_pkt->outer_ip);
	if(uncomp_pkt->ip_hdr_nr > 1)
	{
		inner_ip_hdr = ip_get_raw_data(&uncomp_pkt->inner_ip);
	}
	else
	{
		inner_ip_hdr = NULL;
	}
	next_header = uncomp_pkt->transport->data;

	/* compute CRC on CRC-STATIC fields */
	if(rfc3095_ctxt->is_crc_static_3_cached_valid && crc_type == ROHC_CRC_TYPE_3)
	{
		crc = rfc3095_ctxt->crc_static_3_cached;
		rohc_comp_debug(context, "use CRC-STATIC-3 = 0x%x from cache", crc);
	}
	else if(rfc3095_ctxt->is_crc_static_7_cached_valid && crc_type == ROHC_CRC_TYPE_7)
	{
		crc = rfc3095_ctxt->crc_static_7_cached;
		rohc_comp_debug(context, "use CRC-STATIC-7 = 0x%x from cache", crc);
	}
	else
	{
		crc = rfc3095_ctxt->compute_crc_static(outer_ip_hdr, inner_ip_hdr, next_header,
		                                       crc_type, crc, crc_table);
		rohc_comp_debug(context, "compute CRC-STATIC-%d = 0x%x from packet",
		                crc_type, crc);

		switch(crc_type)
		{
			case ROHC_CRC_TYPE_3:
				rfc3095_ctxt->crc_static_3_cached = crc;
				rfc3095_ctxt->is_crc_static_3_cached_valid = true;
				break;
			case ROHC_CRC_TYPE_7:
				rfc3095_ctxt->crc_static_7_cached = crc;
				rfc3095_ctxt->is_crc_static_7_cached_valid = true;
				break;
			default:
				break;
		}
	}

	/* compute CRC on CRC-DYNAMIC fields */
	crc = rfc3095_ctxt->compute_crc_dynamic(outer_ip_hdr, inner_ip_hdr, next_header,
	                                        crc_type, crc, crc_table);

	return crc;
}


/**
 * @brief Update the compression context with the successfully compressed packet
 *
 * @param context     The compression context to update
 * @param uncomp_pkt  The uncompressed packet that updates the context
 */
static void update_context(struct rohc_comp_ctxt *const context,
                           const struct net_pkt *const uncomp_pkt)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* update the context with the new headers */
	update_context_ip_hdr(&rfc3095_ctxt->outer_ip_flags,
	                      &uncomp_pkt->outer_ip);

	if(uncomp_pkt->ip_hdr_nr > 1)
	{
		update_context_ip_hdr(&rfc3095_ctxt->inner_ip_flags,
		                      &uncomp_pkt->inner_ip);
	}
}


/**
 * @brief Update the IP information with the IP header
 *
 * @param ip_flags  The IP context to update
 * @param ip        The uncompressed IP header that updates the context
 */
static void update_context_ip_hdr(struct ip_header_info *const ip_flags,
                                  const struct ip_packet *const ip)
{
	ip_flags->is_first_header = false;

	if(ip_get_version(ip) == IPV4)
	{
		ip_flags->info.v4.old_ip = *(ipv4_get_header(ip));
		ip_flags->info.v4.old_rnd = ip_flags->info.v4.rnd;
		ip_flags->info.v4.old_nbo = ip_flags->info.v4.nbo;
		ip_flags->info.v4.old_sid = ip_flags->info.v4.sid;
	}
}


/**
 * @brief Check if the static parts of the context changed in any of the two
 *        IP headers.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet
 * @return            The number of static fields that changed
 */
static int changed_static_both_hdr(struct rohc_comp_ctxt *const context,
                                   const struct net_pkt *const uncomp_pkt)
{
	/* TODO: should not alter the counters in the context there */
	int nb_fields = 0; /* number of fields that changed */
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	nb_fields = changed_static_one_hdr(context, rfc3095_ctxt->tmp.changed_fields,
	                                   &rfc3095_ctxt->outer_ip_flags);

	if(uncomp_pkt->ip_hdr_nr > 1)
	{
		nb_fields += changed_static_one_hdr(context,
		                                    rfc3095_ctxt->tmp.changed_fields2,
		                                    &rfc3095_ctxt->inner_ip_flags);
	}

	return nb_fields;
}


/**
 * @brief Check if the static part of the context changed in the new IP packet.
 *
 * The fields classified as STATIC-DEF by RFC do not need to be checked for
 * change. These fields are constant for all packets in a stream (ie. a
 * profile context). So, the Source Address and Destination Address fields are
 * not checked for change for both IPv4 and IPv6. The Flow Label is not checked
 * for IPv6.
 *
 * Although not classified as STATIC-DEF, the Version field is the same for
 * all packets in a stream (ie. a profile context) and therefore does not need
 * to be checked for change neither for IPv4 nor IPv6.
 *
 * Although classified as STATIC, the IPv4 Don't Fragment flag is not part of
 * the static initialization, but of the dynamic initialization.
 *
 * Summary:
 *  - For IPv4, check the Protocol field for change.
 *  - For IPv6, check the Next Header field for change.
 *
 * @param context        The compression context
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param header_info    The header info stored in the profile
 * @return               The number of fields that changed
 */
static int changed_static_one_hdr(struct rohc_comp_ctxt *const context,
                                  const unsigned short changed_fields,
                                  struct ip_header_info *const header_info)
{
	/* TODO: should not alter the counters in the context there */
	int nb_fields = 0; /* number of fields that changed */

	/* check the IPv4 Protocol / IPv6 Next Header field for change */
	if(is_field_changed(changed_fields, MOD_PROTOCOL) ||
	   header_info->protocol_count < MAX_FO_COUNT)
	{
		rohc_comp_debug(context, "protocol_count %zu", header_info->protocol_count);

		if(is_field_changed(changed_fields, MOD_PROTOCOL))
		{
			header_info->protocol_count = 0;
			context->fo_count = 0;
		}
		nb_fields += 1;
	}

	return nb_fields;
}


/**
 * @brief Check if the dynamic parts of the context changed in any of the two
 *        IP headers.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet
 * @return            The number of dynamic fields that changed
 */
static int changed_dynamic_both_hdr(struct rohc_comp_ctxt *const context,
                                    const struct net_pkt *const uncomp_pkt)
{
	/* TODO: should not alter the counters in the context there */
	int nb_fields = 0; /* number of fields that changed */
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	rohc_comp_debug(context, "check for changed fields in the outer IP header");
	nb_fields = changed_dynamic_one_hdr(context, rfc3095_ctxt->tmp.changed_fields,
	                                    &rfc3095_ctxt->outer_ip_flags,
	                                    &uncomp_pkt->outer_ip);

	if(uncomp_pkt->ip_hdr_nr > 1)
	{
		rohc_comp_debug(context, "check for changed fields in the inner IP header");
		nb_fields += changed_dynamic_one_hdr(context,
		                                     rfc3095_ctxt->tmp.changed_fields2,
		                                     &rfc3095_ctxt->inner_ip_flags,
		                                     &uncomp_pkt->inner_ip);
	}

	return nb_fields;
}


/**
 * @brief Check if the dynamic part of the context changed in the IP packet.
 *
 * The fields classified as CHANGING by RFC need to be checked for change. The
 * fields are:
 *  - the TOS, IP-ID and TTL fields for IPv4,
 *  - the TC and HL fields for IPv6.
 *
 * The IP-ID changes are managed outside of this function.
 *
 * Although classified as STATIC, the IPv4 Don't Fragment flag is not part of
 * the static initialization, but of the dynamic initialization. It needs to be
 * checked for change.
 *
 * Other flags are checked for change for IPv4. There are IP-ID related flags:
 *  - RND: is the IP-ID random?
 *  - NBO: is the IP-ID in Network Byte Order?
 *  - SID: is the IP-ID static?
 *
 * @param context        The compression context
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @return               The number of fields that changed
 */
static int changed_dynamic_one_hdr(struct rohc_comp_ctxt *const context,
                                   const unsigned short changed_fields,
                                   struct ip_header_info *const header_info,
                                   const struct ip_packet *const ip)
{
	/* TODO: should not alter the counters in the context there */
	size_t nb_fields = 0; /* number of fields that changed */

	/* check the Type Of Service / Traffic Class field for change */
	if(is_field_changed(changed_fields, MOD_TOS) ||
	   header_info->tos_count < MAX_FO_COUNT)
	{
		if(is_field_changed(changed_fields, MOD_TOS))
		{
			rohc_comp_debug(context, "TOS/TC changed in the current packet");
			header_info->tos_count = 0;
			context->fo_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "TOS/TC changed in the last few packets");
		}
		nb_fields++;
	}

	/* check the Time To Live / Hop Limit field for change */
	if(is_field_changed(changed_fields, MOD_TTL) ||
	   header_info->ttl_count < MAX_FO_COUNT)
	{
		if(is_field_changed(changed_fields, MOD_TTL))
		{
			rohc_comp_debug(context, "TTL/HL changed in the current packet");
			header_info->ttl_count = 0;
			context->fo_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "TTL/HL changed in the last few packets");
		}
		nb_fields++;
	}

	/* IPv4 only checks */
	if(ip_get_version(ip) == IPV4)
	{
		size_t nb_flags = 0; /* number of flags that changed */
		uint8_t old_df;
		uint8_t df;

		/* check the Don't Fragment flag for change (IPv4 only) */
		df = ipv4_get_df(ip);
		old_df = header_info->info.v4.old_ip.df;
		if(df != old_df || header_info->info.v4.df_count < MAX_FO_COUNT)
		{
			if(df != old_df)
			{
				rohc_comp_debug(context, "DF changed in the current packet");
				header_info->info.v4.df_count = 0;
				context->fo_count = 0;
			}
			else
			{
				rohc_comp_debug(context, "DF changed in the last few packets");
			}
			nb_fields++;
		}

		/* check the RND flag for change (IPv4 only) */
		if(header_info->info.v4.rnd != header_info->info.v4.old_rnd ||
		   header_info->info.v4.rnd_count < MAX_FO_COUNT)
		{
			if(header_info->info.v4.rnd != header_info->info.v4.old_rnd)
			{
				rohc_comp_debug(context, "RND changed (0x%x -> 0x%x) in the "
				                "current packet", header_info->info.v4.old_rnd,
				                header_info->info.v4.rnd);
				header_info->info.v4.rnd_count = 0;
				context->fo_count = 0;
			}
			else
			{
				rohc_comp_debug(context, "RND changed in the last few packets");
			}
			nb_flags++;
		}

		/*  check the NBO flag for change (IPv4 only) */
		if(header_info->info.v4.nbo != header_info->info.v4.old_nbo ||
		   header_info->info.v4.nbo_count < MAX_FO_COUNT)
		{
			if(header_info->info.v4.nbo != header_info->info.v4.old_nbo)
			{
				rohc_comp_debug(context, "NBO changed (0x%x -> 0x%x) in the "
				                "current packet", header_info->info.v4.old_nbo,
				                header_info->info.v4.nbo);
				header_info->info.v4.nbo_count = 0;
				context->fo_count = 0;
			}
			else
			{
				rohc_comp_debug(context, "NBO changed in the last few packets");
			}
			nb_flags += 1;
		}

		if(nb_flags > 0)
		{
			nb_fields++;
		}

		/*  check the SID flag for change (IPv4 only) */
		if(header_info->info.v4.sid != header_info->info.v4.old_sid ||
		   header_info->info.v4.sid_count < MAX_FO_COUNT)
		{
			if(header_info->info.v4.sid != header_info->info.v4.old_sid)
			{
				rohc_comp_debug(context, "SID changed (0x%x -> 0x%x) in the "
				                "current packet", header_info->info.v4.old_sid,
				                header_info->info.v4.sid);
				header_info->info.v4.sid_count = 0;
				context->fo_count = 0;
			}
			else
			{
				rohc_comp_debug(context, "SID changed in the last few packets");
			}
		}
	}

	return nb_fields;
}


/**
 * @brief Find the IP fields that changed between the profile and a new
 *        IP packet.
 *
 * Only some fields are checked for change in the compression process, so
 * only check these ones to avoid useless work. The fields to check are:
 * TOS/TC, TTL/HL and Protocol/Next Header.
 *
 * @param context        The compression context
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @return               The bitpattern that indicates which field changed
 */
static unsigned short detect_changed_fields(const struct rohc_comp_ctxt *const context,
                                            struct ip_header_info *const header_info, /* TODO: add const */
                                            const struct ip_packet *const ip)
{
	unsigned short ret_value = 0;
	uint8_t old_tos;
	uint8_t new_tos;
	uint8_t old_ttl;
	uint8_t new_ttl;
	uint8_t old_protocol;
	uint8_t new_protocol;

	assert(context != NULL);
	assert(header_info != NULL);
	assert(ip != NULL);

	if(ip_get_version(ip) == IPV4)
	{
		const struct ipv4_hdr *old_ip;

		old_ip = &header_info->info.v4.old_ip;
		old_tos = old_ip->tos;
		old_ttl = old_ip->ttl;
		old_protocol = old_ip->protocol;
	}

	new_tos = ip_get_tos(ip);
	if(old_tos != new_tos)
	{
		rohc_comp_debug(context, "TOS/TC changed from 0x%02x to 0x%02x",
		                old_tos, new_tos);
		ret_value |= MOD_TOS;
	}

	new_ttl = ip_get_ttl(ip);
	if(old_ttl != new_ttl)
	{
		rohc_comp_debug(context, "TTL/HL changed from 0x%02x to 0x%02x",
		                old_ttl, new_ttl);
		ret_value |= MOD_TTL;
	}

	new_protocol = ip_get_protocol(ip);
	if(old_protocol != new_protocol)
	{
		rohc_comp_debug(context, "Protocol/NH changed from 0x%02x to 0x%02x",
		                old_protocol, new_protocol);
		ret_value |= MOD_PROTOCOL;
	}

	return ret_value;
}


/**
 * @brief Detect the behaviour of the IP-ID fields of the IPv4 headers
 *
 * Detect how the IP-ID fields behave:
 *  - constant (not handled yet),
 *  - increase in Network Bit Order (NBO),
 *  - increase in Little Endian,
 *  - randomly.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet
 */
static void detect_ip_id_behaviours(struct rohc_comp_ctxt *const context,
                                    const struct net_pkt *const uncomp_pkt)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	assert(context != NULL);
	assert(uncomp_pkt != NULL);

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* detect IP-ID behaviour for the outer IP header if IPv4 */
	if(ip_get_version(&uncomp_pkt->outer_ip) == IPV4)
	{
		detect_ip_id_behaviour(context, &rfc3095_ctxt->outer_ip_flags,
		                       &uncomp_pkt->outer_ip);
	}

	/* detect IP-ID behaviour for the inner IP header if present and IPv4 */
	if(uncomp_pkt->ip_hdr_nr > 1 &&
	   ip_get_version(&uncomp_pkt->inner_ip) == IPV4)
	{
		detect_ip_id_behaviour(context, &rfc3095_ctxt->inner_ip_flags,
		                       &uncomp_pkt->inner_ip);
	}
}


/**
 * @brief Detect the behaviour of the IP-ID field of the given IPv4 header
 *
 * Detect how the IP-ID field behave:
 *  - constant,
 *  - increase in Network Bit Order (NBO),
 *  - increase in Little Endian,
 *  - randomly.
 *
 * @param context      The compression context
 * @param header_info  The header info stored in the profile
 * @param ip           One IPv4 header
 */
static void detect_ip_id_behaviour(const struct rohc_comp_ctxt *const context,
                                   struct ip_header_info *const header_info,
                                   const struct ip_packet *const ip)
{
	rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	            ip_get_version(ip) == IPV4, error,
	            "cannot check IP-ID behaviour with IPv6");

	if(header_info->is_first_header)
	{
		/* IP-ID behaviour cannot be detected for the first header (2 headers are
		 * needed), so consider that IP-ID is not random/static and in NBO. */
		rohc_comp_debug(context, "no previous IP-ID, consider non-random/static "
		                "and NBO");
		header_info->info.v4.rnd = 0;
		header_info->info.v4.nbo = 1;
		header_info->info.v4.sid = 0;
	}
	else
	{
		/* we have seen at least one header before this one, so we can (try to)
		 * detect IP-ID behaviour */

		uint16_t old_id; /* the IP-ID of the previous IPv4 header */
		uint16_t new_id; /* the IP-ID of the IPv4 header being compressed */

		old_id = rohc_ntoh16(header_info->info.v4.old_ip.id);
		new_id = rohc_ntoh16(ipv4_get_id(ip));

		rohc_comp_debug(context, "1) old_id = 0x%04x new_id = 0x%04x",
		                old_id, new_id);

		if(new_id == old_id)
		{
			/* previous and current IP-ID values are equal: IP-ID is constant */
			rohc_comp_debug(context, "IP-ID is constant (SID detected)");
			header_info->info.v4.rnd = 0;
			header_info->info.v4.nbo = 1;
			header_info->info.v4.sid = 1;
		}
		else if(is_ip_id_increasing(old_id, new_id))
		{
			/* IP-ID is increasing in NBO */
			rohc_comp_debug(context, "IP-ID is increasing in NBO");
			header_info->info.v4.rnd = 0;
			header_info->info.v4.nbo = 1;
			header_info->info.v4.sid = 0;
		}
		else
		{
			/* change byte ordering and check behaviour again */
			old_id = swab16(old_id);
			new_id = swab16(new_id);

			rohc_comp_debug(context, "2) old_id = 0x%04x new_id = 0x%04x",
			                old_id, new_id);

			if(is_ip_id_increasing(old_id, new_id))
			{
				/* IP-ID is increasing in Little Endian */
				rohc_comp_debug(context, "IP-ID is increasing in Little Endian");
				header_info->info.v4.rnd = 0;
				header_info->info.v4.nbo = 0;
				header_info->info.v4.sid = 0;
			}
			else
			{
				rohc_comp_debug(context, "IP-ID is random (RND detected)");
				header_info->info.v4.rnd = 1;
				header_info->info.v4.nbo = 1; /* do not change bit order if RND */
				header_info->info.v4.sid = 0;
			}
		}
	}

	rohc_comp_debug(context, "NBO = %d, RND = %d, SID = %d",
	                header_info->info.v4.nbo, header_info->info.v4.rnd,
	                header_info->info.v4.sid);

error:
	;
}


/*
 * Definitions of main private functions
 */


/**
 * @brief Encode uncompressed fields with the corresponding encoding scheme
 *
 * @param context      The compression context
 * @param uncomp_pkt   The uncompressed packet to encode
 * @return             true in case of success, false otherwise
 */
static bool encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                 const struct net_pkt *const uncomp_pkt)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	assert(uncomp_pkt != NULL);

	rohc_comp_debug(context, "compressor is in state %u", context->state);

	/* always update the info related to the SN */
	{
		rohc_comp_debug(context, "new SN = %u / 0x%x", rfc3095_ctxt->sn,
		                rfc3095_ctxt->sn);

		/* how many bits are required to encode the new SN ? */
		rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 =
			wlsb_get_k_16bits(&rfc3095_ctxt->sn_window, rfc3095_ctxt->sn);
		rfc3095_ctxt->tmp.nr_sn_bits_less_equal_than_4 =
			rfc3095_ctxt->tmp.nr_sn_bits_more_than_4;
		rohc_comp_debug(context, "SN can%s be encoded with %zu bits in a field "
		                "smaller than or equal to 4 bits",
		                (rfc3095_ctxt->tmp.nr_sn_bits_less_equal_than_4 <= 4 ? "" : "not"),
		                rfc3095_ctxt->tmp.nr_sn_bits_less_equal_than_4);
		rohc_comp_debug(context, "SN can%s be encoded with %zu bits in a field "
		                "strictly larger than 4 bits",
		                (rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 > 4 ? "" : "not"),
		                rfc3095_ctxt->tmp.nr_sn_bits_more_than_4);

		/* add the new SN to the W-LSB encoding object */
		c_add_wlsb(&rfc3095_ctxt->sn_window, rfc3095_ctxt->sn, rfc3095_ctxt->sn);
	}

	/* update info related to the IP-ID of the outer header
	 * only if header is IPv4 */
	if(ip_get_version(&uncomp_pkt->outer_ip) == IPV4)
	{
		/* compute the new IP-ID / SN delta */
		rfc3095_ctxt->outer_ip_flags.info.v4.id_delta =
			rohc_ntoh16(ipv4_get_id_nbo(&uncomp_pkt->outer_ip,
			                            rfc3095_ctxt->outer_ip_flags.info.v4.nbo)) -
			rfc3095_ctxt->sn;
		rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (NBO = %d, "
		                "RND = %d, SID = %d)",
		                rfc3095_ctxt->outer_ip_flags.info.v4.id_delta,
		                rfc3095_ctxt->outer_ip_flags.info.v4.id_delta,
		                rfc3095_ctxt->outer_ip_flags.info.v4.nbo,
		                rfc3095_ctxt->outer_ip_flags.info.v4.rnd,
		                rfc3095_ctxt->outer_ip_flags.info.v4.sid);

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(rfc3095_ctxt->outer_ip_flags.info.v4.sid)
		{
			/* IP-ID is constant, no IP-ID bit to transmit */
			rfc3095_ctxt->tmp.nr_ip_id_bits = 0;
			rohc_comp_debug(context, "outer IP-ID is constant, no IP-ID bit to "
			                "transmit");
		}
		else
		{
			/* send only required bits in FO or SO states */
			rfc3095_ctxt->tmp.nr_ip_id_bits =
				wlsb_get_k_16bits(&rfc3095_ctxt->outer_ip_flags.info.v4.ip_id_window,
				                  rfc3095_ctxt->outer_ip_flags.info.v4.id_delta);
		}
		rohc_comp_debug(context, "%zd bits are required to encode new outer "
		                "IP-ID delta", rfc3095_ctxt->tmp.nr_ip_id_bits);

		/* add the new IP-ID / SN delta to the W-LSB encoding object */
		c_add_wlsb(&rfc3095_ctxt->outer_ip_flags.info.v4.ip_id_window, rfc3095_ctxt->sn,
		           rfc3095_ctxt->outer_ip_flags.info.v4.id_delta);
	}
	
	/* update info related to the IP-ID of the inner header
	 * only if header is IPv4 */
	if(uncomp_pkt->ip_hdr_nr > 1 &&
	   ip_get_version(&uncomp_pkt->inner_ip) == IPV4)
	{
		/* compute the new IP-ID / SN delta */
		rfc3095_ctxt->inner_ip_flags.info.v4.id_delta =
			rohc_ntoh16(ipv4_get_id_nbo(&uncomp_pkt->inner_ip,
			                            rfc3095_ctxt->inner_ip_flags.info.v4.nbo)) -
			rfc3095_ctxt->sn;
		rohc_comp_debug(context, "new inner IP-ID delta = 0x%x / %u (NBO = %d, "
		                "RND = %d, SID = %d)",
		                rfc3095_ctxt->inner_ip_flags.info.v4.id_delta,
		                rfc3095_ctxt->inner_ip_flags.info.v4.id_delta,
		                rfc3095_ctxt->inner_ip_flags.info.v4.nbo,
		                rfc3095_ctxt->inner_ip_flags.info.v4.rnd,
		                rfc3095_ctxt->inner_ip_flags.info.v4.sid);

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(rfc3095_ctxt->inner_ip_flags.info.v4.sid)
		{
			/* IP-ID is constant, no IP-ID bit to transmit */
			rfc3095_ctxt->tmp.nr_ip_id_bits2 = 0;
			rohc_comp_debug(context, "inner IP-ID is constant, no IP-ID bit to "
			                "transmit");
		}
		else
		{
			/* send only required bits in FO or SO states */
			rfc3095_ctxt->tmp.nr_ip_id_bits2 =
				wlsb_get_k_16bits(&rfc3095_ctxt->inner_ip_flags.info.v4.ip_id_window,
				                  rfc3095_ctxt->inner_ip_flags.info.v4.id_delta);
		}
		rohc_comp_debug(context, "%zd bits are required to encode new inner "
		                "IP-ID delta", rfc3095_ctxt->tmp.nr_ip_id_bits2);

		/* add the new IP-ID / SN delta to the W-LSB encoding object */
		c_add_wlsb(&rfc3095_ctxt->inner_ip_flags.info.v4.ip_id_window, rfc3095_ctxt->sn,
		           rfc3095_ctxt->inner_ip_flags.info.v4.id_delta);
	}

	/* update info related to transport header */
	if(rfc3095_ctxt->encode_uncomp_fields != NULL &&
	   !rfc3095_ctxt->encode_uncomp_fields(context, uncomp_pkt))
	{
		rohc_comp_warn(context, "failed to encode uncompressed next header "
		               "fields");
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Decide what extension shall be used in the UO-1-ID/UOR-2 packet.
 *
 * Extensions 0, 1 & 2 are IPv4 only because of the IP-ID.
 *
 * @param context The compression context
 * @return        The extension code among ROHC_EXT_NONE, ROHC_EXT_0,
 *                ROHC_EXT_1 and ROHC_EXT_3 if successful,
 *                ROHC_EXT_UNKNOWN otherwise
 */
rohc_ext_t decide_extension(const struct rohc_comp_ctxt *const context)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	size_t nr_innermost_ip_id_bits;
	size_t nr_outermost_ip_id_bits;
	rohc_ext_t ext;

	/* force extension type 3 if at least one static or dynamic field changed */
	if(rfc3095_ctxt->tmp.send_static > 0 || rfc3095_ctxt->tmp.send_dynamic > 0)
	{
		rohc_comp_debug(context, "force EXT-3 because at least one static or "
		                "dynamic field changed");
		ext = ROHC_EXT_3;
	}
	else
	{
		/* determine the number of IP-ID bits and the IP-ID offset of the
		 * innermost IPv4 header with non-random IP-ID */
		rohc_get_ipid_bits(context, &nr_innermost_ip_id_bits,
		                   &nr_outermost_ip_id_bits);

		switch(rfc3095_ctxt->tmp.packet_type)
		{
			case ROHC_PACKET_UOR_2:
				ext = decide_extension_uor2(context, nr_innermost_ip_id_bits,
				                            nr_outermost_ip_id_bits);
				break;
			default:
				rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				            false, error, "bad packet type (%d)",
				            rfc3095_ctxt->tmp.packet_type);
		}
	}

	return ext;

error:
	return ROHC_EXT_UNKNOWN;
}


/**
 * @brief Decide what extension shall be used in the UOR-2 packet (non-RTP).
 *
 * Extensions 0, 1 & 2 are IPv4 only because of the IP-ID.
 *
 * @param context                  The compression context
 * @param nr_innermost_ip_id_bits  The number of IP-ID bits of the innermost
 *                                 IPv4 header
 * @param nr_outermost_ip_id_bits  The number of IP-ID bits of the outermost
 *                                 IPv4 header
 * @return                         The extension code among ROHC_EXT_NONE,
 *                                 ROHC_EXT_0, ROHC_EXT_1 and ROHC_EXT_3
 */
static rohc_ext_t decide_extension_uor2(const struct rohc_comp_ctxt *const context,
                                        const size_t nr_innermost_ip_id_bits,
                                        const size_t nr_outermost_ip_id_bits)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	rohc_ext_t ext;

	if(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 5 &&
	   nr_innermost_ip_id_bits == 0 &&
	   nr_outermost_ip_id_bits == 0)
	{
		ext = ROHC_EXT_NONE;
	}
	else if(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 8 &&
	        nr_innermost_ip_id_bits != 0 && nr_innermost_ip_id_bits <= 3 &&
	        nr_outermost_ip_id_bits == 0)
	{
		ext = ROHC_EXT_0;
	}
	else if(rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 8 &&
	        nr_innermost_ip_id_bits != 0 && nr_innermost_ip_id_bits <= 11 &&
	        nr_outermost_ip_id_bits == 0)
	{
		ext = ROHC_EXT_1;
	}
	else if(rfc3095_ctxt->ip_hdr_nr > 1 &&
	        rfc3095_ctxt->tmp.nr_sn_bits_more_than_4 <= 8 &&
	        nr_innermost_ip_id_bits != 0 && nr_innermost_ip_id_bits <= 8 &&
	        nr_outermost_ip_id_bits <= 11)
	{
		ext = ROHC_EXT_2;
	}
	else
	{
		ext = ROHC_EXT_3;
	}

	return ext;
}

/**
 * @brief Determine the number of IP-ID bits and the IP-ID offset of the
 *        innermost IPv4 header with non-random IP-ID
 *
 * @param context  The compression context
 * @param pos      OUT: The position of the header
 * @param nr_bits  OUT: the number of IP-ID bits of the found header
 * @param offset   OUT: the IP-ID offset of the found header
 */
static void rohc_get_innermost_ipv4_non_rnd(const struct rohc_comp_ctxt *const context,
                                            ip_header_pos_t *const pos,
                                            size_t *const nr_bits,
                                            uint16_t *const offset)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	assert(pos != NULL);
	assert(nr_bits != NULL);
	assert(offset != NULL);

	if(rfc3095_ctxt->ip_hdr_nr > 1 &&
	   rfc3095_ctxt->inner_ip_flags.version == IPV4 &&
	   rfc3095_ctxt->inner_ip_flags.info.v4.rnd == 0)
	{
		/* inner IP header exists and is IPv4 with a non-random IP-ID */
		*pos = ROHC_IP_HDR_SECOND;
		*nr_bits = rfc3095_ctxt->tmp.nr_ip_id_bits2;
		*offset = rfc3095_ctxt->inner_ip_flags.info.v4.id_delta;
	}
	else if(rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
	        rfc3095_ctxt->outer_ip_flags.info.v4.rnd == 0)
	{
		/* outer IP header is IPv4 with a non-random IP-ID */
		*pos = ROHC_IP_HDR_FIRST;
		*nr_bits = rfc3095_ctxt->tmp.nr_ip_id_bits;
		*offset = rfc3095_ctxt->outer_ip_flags.info.v4.id_delta;
	}
	else
	{
		/* there is no IPv4 header with a non-random IP-ID */
		*pos = ROHC_IP_HDR_NONE;
		*nr_bits = 0;
		*offset = 0;
	}
}


/**
 * @brief Get the number of non-random outer/inner IP-ID bits
 *
 * @param context            The compression context
 * @param nr_innermost_bits  OUT: the maximum number of IP-ID bits
 *                                for the innermost IPv4 header
 * @param nr_outermost_bits  OUT: the maximum number of IP-ID bits
 *                                for the outermost IP header
 */
void rohc_get_ipid_bits(const struct rohc_comp_ctxt *const context,
                        size_t *const nr_innermost_bits,
                        size_t *const nr_outermost_bits)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;

	if(rfc3095_ctxt->ip_hdr_nr > 1 &&
	   rfc3095_ctxt->inner_ip_flags.version == IPV4 &&
	   rfc3095_ctxt->inner_ip_flags.info.v4.rnd == 0)
	{
		/* inner IP header exists and is IPv4 with a non-random IP-ID */
		*nr_innermost_bits = rfc3095_ctxt->tmp.nr_ip_id_bits2;

		/* how many bits for the outer IP-ID? */
		if(rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
		   rfc3095_ctxt->outer_ip_flags.info.v4.rnd == 0)
		{
			*nr_outermost_bits = rfc3095_ctxt->tmp.nr_ip_id_bits;
		}
		else
		{
			*nr_outermost_bits = 0;
		}
	}
	else if(rfc3095_ctxt->outer_ip_flags.version == IPV4 &&
	        rfc3095_ctxt->outer_ip_flags.info.v4.rnd == 0)
	{
		/* outer IP header is the innermost IPv4 with a non-random IP-ID */
		*nr_innermost_bits = rfc3095_ctxt->tmp.nr_ip_id_bits;
		*nr_outermost_bits = 0;
	}
	else
	{
		/* there is no IPv4 header with a non-random IP-ID */
		*nr_innermost_bits = 0;
		*nr_outermost_bits = 0;
	}
}


/**
 * @brief Are the given SN field sizes possible?
 *
 * @param rfc3095_ctxt  The compression context
 * @param bits_nr       The base number of SN bits
 * @param add_bits_nr   The additional number of SN bits
 * @return              true if the SN field is usable, false if not
 */
bool rohc_comp_rfc3095_is_sn_possible(const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt,
                                      const size_t bits_nr,
                                      const size_t add_bits_nr)
{
	const size_t required_bits =
		(bits_nr <= 4 ? rfc3095_ctxt->tmp.nr_sn_bits_less_equal_than_4 :
		 rfc3095_ctxt->tmp.nr_sn_bits_more_than_4);
	const size_t required_add_bits =
		((bits_nr + add_bits_nr) <= 4 ? rfc3095_ctxt->tmp.nr_sn_bits_less_equal_than_4 :
		 rfc3095_ctxt->tmp.nr_sn_bits_more_than_4);

	return (required_bits <= bits_nr || required_add_bits <= (bits_nr + add_bits_nr));
}


/**
 * @brief Determine the values of the I and I2 flags for UO* extension 3
 *
 * @param context                      The compression context
 * @param uncomp_pkt                   The uncompressed packet to encode
 * @param packet_type                  The type of packet that is being built
 * @param nr_ip_id_bits                The number of IP-ID bits for the first
 *                                     IP header
 * @param nr_ip_id_bits2               The number of IP-ID bits for the second
 *                                     IP header (if any)
 * @param[out] innermost_ipv4_non_rnd  The position of the innermost IPv4 header
 *                                     with a non-random IP-ID field
 * @param[out] I                       The value of the I flag in UO extension 3,
 *                                     ie. whether the innermost IPv4 header with
 *                                     a non-random IP-ID needs to transmit some
 *                                     IP-ID bits
 * @param[out] I2                      The value of the I2 flag in UO extension 3,
 *                                     ie. whether the 2nd innermost IPv4 header
 *                                     with a non-random IP-ID needs to transmit
 *                                     some IP-ID bits
 */
static void rohc_comp_rfc3095_get_ext3_I_flags(const struct rohc_comp_ctxt *const context,
                                               const struct net_pkt *const uncomp_pkt,
                                               const rohc_packet_t packet_type,
                                               const size_t nr_ip_id_bits,
                                               const size_t nr_ip_id_bits2,
                                               ip_header_pos_t *const innermost_ipv4_non_rnd,
                                               uint8_t *const I,
                                               uint8_t *const I2)
{
	const struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt = context->specific;
	assert(packet_type>=0);
	if(uncomp_pkt->ip_hdr_nr == 1)
	{
		const struct ip_packet *const inner_ip = &uncomp_pkt->outer_ip;
		const struct ip_header_info *const inner_ip_flags = &rfc3095_ctxt->outer_ip_flags;

		/* if the innermost IP header is IPv4 with non-random IP-ID, check if
		 * the I bit must be set */
		if(ip_get_version(inner_ip) == IPV4 && inner_ip_flags->info.v4.rnd == 0)
		{
			*innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;

			if(nr_ip_id_bits > 0)
			{
				*I = 1;
			}
			else if(inner_ip_flags->info.v4.rnd_count < MAX_FO_COUNT)
			{
				*I = 1;
			}
			else
			{
				*I = 0;
			}
		}
		else
		{
			/* the IP header is not 'IPv4 with non-random IP-ID' */
			*innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
			*I = 0;
		}

		/* no second IP header */
		*I2 = 0;
	}
	else /* double IP headers */
	{
		const struct ip_packet *const inner_ip = &uncomp_pkt->inner_ip;
		const struct ip_header_info *const inner_ip_flags = &rfc3095_ctxt->inner_ip_flags;
		const struct ip_packet *const outer_ip = &uncomp_pkt->outer_ip;
		const struct ip_header_info *const outer_ip_flags = &rfc3095_ctxt->outer_ip_flags;

		/* set the I bit if some bits (depends on packet type) of the innermost
		 * IPv4 header with non-random IP-ID must be transmitted */
		if(ip_get_version(inner_ip) == IPV4 && inner_ip_flags->info.v4.rnd == 0)
		{
			/* inner IP header is IPv4 with non-random IP-ID */
			*innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;

			if(nr_ip_id_bits2 > 0)
			{
				*I = 1;
			}
			else if(inner_ip_flags->info.v4.rnd_count < MAX_FO_COUNT)
			{
				*I = 1;
			}
			else
			{
				*I = 0;
			}

			/* the innermost IPv4 header with non-random IP-ID is the inner IP
			 * header, maybe there is a need for a second IP-ID for the outer
			 * IP header */
			if(ip_get_version(outer_ip) == IPV4 && outer_ip_flags->info.v4.rnd == 0)
			{
				/* outer IP header is also IPv4 with non-random IP-ID */
				if(nr_ip_id_bits > 0)
				{
					*I2 = 1;
				}
				else if(outer_ip_flags->info.v4.rnd_count < MAX_FO_COUNT)
				{
					*I2 = 1;
				}
				else
				{
					*I2 = 0;
				}
			}
			else
			{
				*I2 = 0;
			}
		}
		else if(ip_get_version(outer_ip) == IPV4 && outer_ip_flags->info.v4.rnd == 0)
		{
			/* inner IP header is not 'IPv4 with non-random IP-ID', but outer
			 * IP header is */
			*innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;

			if(nr_ip_id_bits > 0)
			{
				*I = 1;
			}
			else if(outer_ip_flags->info.v4.rnd_count < MAX_FO_COUNT)
			{
				*I = 1;
			}
			else
			{
				*I = 0;
			}

			/* the innermost IPv4 header with non-random IP-ID is the outer IP
			 * header, so there is no need for a second IP-ID field */
			*I2 = 0;
		}
		else
		{
			/* none of the 2 IP headers are IPv4 with non-random IP-ID */
			*innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
			*I = 0;
			*I2 = 0;
		}
	}
}

