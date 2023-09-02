/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2008,2009,2010,2012,2014 Viveris Technologies
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
 * @file   rohc_comp_rfc3095.h
 * @brief  Generic framework for RFC3095-based compression profiles such as
 *         IP-only, UDP, UDP-Lite, ESP, and RTP profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_RFC3095_H
#define ROHC_COMP_RFC3095_H

#include "rohc_comp_internals.h"
#include "rohc_packets.h"
#include "comp_list.h"
#include "ip.h"
#include "crc.h"

#include <stdlib.h>


/**
 * @brief Store information about an IPv4 header between the different
 *        compressions of IP packets.
 *
 * Defines an object that contains counters, flags and structures related to an
 * IPv4 header and that need to be saved between the different compressions of
 * packets. A compression context owns objects like this for the two first
 * IPv4 headers.
 */
struct ipv4_header_info
{
	/// A window to store the IP-ID
	struct c_wlsb ip_id_window;

	/// The previous IP header
	struct ipv4_hdr old_ip;

	/// The number of times the DF field was added to the compressed header
	size_t df_count;
	/// @brief The number of times the IP-ID is specified as random in the
	///        compressed header
	size_t rnd_count;
	/// @brief The number of times the IP-ID is specified as coded in Network
	///        Byte Order (NBO) in the compressed header
	size_t nbo_count;
	/// @brief The number of times the IP-ID is specified as static in the
	///        compressed header
	size_t sid_count;

	/// Whether the IP-ID is considered as random or not
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not
	int nbo;
	/// Whether the IP-ID is considered as static or not
	int sid;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        random or not
	int old_rnd;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        coded in NBO or not
	int old_nbo;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        static or not
	int old_sid;

	/// The delta between the IP-ID and the current Sequence Number (SN)
	/// (overflow over 16 bits is expected when SN > IP-ID)
	uint16_t id_delta;
};

/**
 * @brief Store information about an IP (IPv4 or IPv6) header between the
 *        different compressions of IP packets.
 */
struct ip_header_info
{
	ip_version version;            ///< The version of the IP header

	/// The number of times the TOS/TC field was added to the compressed header
	size_t tos_count;
	/// The number of times the TTL/HL field was added to the compressed header
	size_t ttl_count;
	/// @brief The number of times the Protocol/Next Header field was added to
	///        the compressed header
	size_t protocol_count;

	/** Whether the old_* members of the struct and in its children are
	 *  initialized or not */
	bool is_first_header;

	union
	{
		struct ipv4_header_info v4; ///< The IPv4-specific header info
	} info;                        ///< The version specific header info
};


/**
 * @brief Structure that contains variables that are used during one single
 *        compression of packet.
 *
 * Structure that contains variables that are temporary, i.e. variables that
 * will only be used for the compression of the current packet. These variables
 * must be reinitialized every time a new packet arrive.
 *
 * @see c_init_tmp_variables
 */
struct generic_tmp_vars
{
	/// The number of fields that changed in the outer IP header
	unsigned short changed_fields;
	/// The number of fields that changed in the inner IP header
	unsigned short changed_fields2;
	/// The number of static fields that changed in the two IP headers
	int send_static;
	/// The number of dynamic fields that changed in the two IP headers
	int send_dynamic;

	/// The number of bits needed to encode the Sequence Number (SN)
	size_t nr_sn_bits_less_equal_than_4;
	/// The number of bits needed to encode the Sequence Number (SN)
	size_t nr_sn_bits_more_than_4;

	/// The number of bits needed to encode the IP-ID of the outer IP header
	size_t nr_ip_id_bits;
	/// The number of bits needed to encode the IP-ID of the inner IP header
	size_t nr_ip_id_bits2;

	/// The type of packet the compressor must send: IR, IR-DYN, UO*
	rohc_packet_t packet_type;
};


/**
 * @brief The generic decompression context for RFC3095-based profiles
 *
 * The object defines the generic context that manages IP(/nextheader) and
 * IP/IP(/nextheader) packets. nextheader is managed by the profile-specific
 * part of the context.
 */
struct rohc_comp_rfc3095_ctxt
{
	/// The Sequence Number (SN), may be 16-bit or 32-bit long
	uint32_t sn;
	/// A window used to encode the SN
	struct c_wlsb sn_window;

	/** The SN of the last packet that updated the context (used to determine
	 * if a positive ACK may cause a transition to a higher compression state) */
	uint32_t msn_of_last_ctxt_updating_pkt;
	/** The W-LSB for non-acknowledged MSN */
	struct c_wlsb msn_non_acked;

	/** The number of IP headers */
	size_t ip_hdr_nr;
	/// Information about the outer IP header
	struct ip_header_info outer_ip_flags;

	/** Whether the cache for the CRC-3 value on CRC-STATIC fields is initialized or not */
	bool is_crc_static_3_cached_valid;
	/** The cache for the CRC-3 value on CRC-STATIC fields */
	uint8_t crc_static_3_cached;
	/** Whether the cache for the CRC-7 value on CRC-STATIC fields is initialized or not */
	bool is_crc_static_7_cached_valid;
	/** The cache for the CRC-7 value on CRC-STATIC fields */
	uint8_t crc_static_7_cached;

	/// Temporary variables that are used during one single compression of packet
	struct generic_tmp_vars tmp;

	/* below are some information and handlers to manage the next header
	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The protocol number registered by IANA for the next header protocol
	unsigned int next_header_proto;
	/// The length of the next header
	unsigned int next_header_len;

	/** The handler for encoding profile-specific uncompressed header fields */
	bool (*encode_uncomp_fields)(struct rohc_comp_ctxt *const context,
	                             const struct net_pkt *const uncomp_pkt)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/// @brief The handler used to decide the state that should be used for the
	///        next packet
	void (*decide_state)(struct rohc_comp_ctxt *const context);
	/** @brief The handler used to decide which packet to send in FO state */
	rohc_packet_t (*decide_FO_packet)(const struct rohc_comp_ctxt *context);
	/** @brief The handler used to decide which packet to send in SO state */
	rohc_packet_t (*decide_SO_packet)(const struct rohc_comp_ctxt *context);

	/** Determine the next SN value */
	uint32_t (*get_next_sn)(const struct rohc_comp_ctxt *const context,
	                        const struct net_pkt *const uncomp_pkt)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/// @brief The handler used to add the static part of the next header to the
	///        ROHC packet
	size_t (*code_static_part)(const struct rohc_comp_ctxt *const context,
	                           const uint8_t *const next_header,
	                           uint8_t *const dest,
	                           const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/// @brief The handler used to add the dynamic part of the next header to the
	///        ROHC pachet
	size_t (*code_dynamic_part)(const struct rohc_comp_ctxt *const context,
	                            const uint8_t *const next_header,
	                            uint8_t *const dest,
	                            const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/// @brief The handler used to add the IR/IR-DYN remainder header to the
	///        ROHC pachet
	int (*code_ir_remainder)(const struct rohc_comp_ctxt *const context,
	                         uint8_t *const dest,
	                         const size_t dest_max_len,
	                         const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/// @brief The handler used to add an additional header in the tail of the
	///        UO-0, UO-1 and UO-2 packets
	size_t (*code_uo_remainder)(const struct rohc_comp_ctxt *const context,
	                            const uint8_t *const next_header,
	                            uint8_t *const dest,
	                            const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/// @brief The handler used to compute the CRC-STATIC value
	uint8_t (*compute_crc_static)(const uint8_t *const ip,
	                              const uint8_t *const ip2,
	                              const uint8_t *const next_header,
	                              const rohc_crc_type_t crc_type,
	                              const uint8_t init_val,
	                              const uint8_t *const crc_table)
		__attribute__((nonnull(1, 3, 6), warn_unused_result));

	/// @brief The handler used to compute the CRC-DYNAMIC value
	uint8_t (*compute_crc_dynamic)(const uint8_t *const ip,
	                               const uint8_t *const ip2,
	                               const uint8_t *const next_header,
	                               const rohc_crc_type_t crc_type,
	                               const uint8_t init_val,
	                               const uint8_t *const crc_table)
		__attribute__((nonnull(1, 3, 6), warn_unused_result));

	/// Profile-specific data
	void *specific;
};


/*
 * Function prototypes.
 */

bool rohc_comp_rfc3095_create(struct rohc_comp_ctxt *const context,
                              const size_t sn_bits_nr,
                              const rohc_lsb_shift_t sn_shift,
                              const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 4)));

void rohc_comp_rfc3095_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

bool rohc_comp_rfc3095_check_profile(const struct rohc_comp *const comp,
                                     const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

int rohc_comp_rfc3095_encode(struct rohc_comp_ctxt *const context,
                             const struct net_pkt *const uncomp_pkt,
                             uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len,
                             rohc_packet_t *const packet_type,
                             size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

void rohc_comp_rfc3095_decide_state(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

void rohc_get_ipid_bits(const struct rohc_comp_ctxt *const context,
                        size_t *const nr_innermost_bits,
                        size_t *const nr_outermost_bits)
	__attribute__((nonnull(1, 2, 3)));

bool rohc_comp_rfc3095_is_sn_possible(const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt,
                                      const size_t bits_nr,
                                      const size_t add_bits_nr)
	__attribute__((warn_unused_result, nonnull(1), pure));


/**
 * @brief Does the outer IP header require to transmit no non-random IP-ID bit?
 *
 * @param ctxt  The generic decompression context
 * @return      true if no required outer IP-ID bit shall be transmitted,
 *              false otherwise
 */
static inline bool no_outer_ip_id_bits_required(const struct rohc_comp_rfc3095_ctxt *const ctxt)
{
	return (ctxt->outer_ip_flags.version != IPV4 ||
	        ctxt->outer_ip_flags.info.v4.rnd == 1 ||
	        ctxt->tmp.nr_ip_id_bits == 0);
}


/**
 * @brief May the outer IP header transmit the required non-random IP-ID bits?
 *
 * @param ctxt               The generic decompression context
 * @param max_ip_id_bits_nr  The maximum number of IP-ID bits that may be transmitted
 * @return                   true if the required IP-ID bits may be transmitted,
 *                           false otherwise
 */
static inline bool is_outer_ip_id_bits_possible(const struct rohc_comp_rfc3095_ctxt *const ctxt,
                                                const size_t max_ip_id_bits_nr)
{
	return (ctxt->outer_ip_flags.version == IPV4 &&
	        ctxt->outer_ip_flags.info.v4.rnd != 1 &&
	        ctxt->tmp.nr_ip_id_bits <= max_ip_id_bits_nr);
}


/**
 * @brief Does the inner IP header require to transmit no non-random IP-ID bit?
 *
 * @param ctxt  The generic decompression context
 * @return      true if no required inner IP-ID bit shall be transmitted,
 *              false otherwise
 */
static inline bool no_inner_ip_id_bits_required(const struct rohc_comp_rfc3095_ctxt *const ctxt)
{
	return (ctxt->tmp.nr_ip_id_bits2 == 0);
}


/**
 * @brief May the inner IP header transmit the required non-random IP-ID bits?
 *
 * @param ctxt               The generic decompression context
 * @param max_ip_id_bits_nr  The maximum number of IP-ID bits that may be transmitted
 * @return                   true if the required IP-ID bits may be transmitted,
 *                           false otherwise
 */
static inline bool is_inner_ip_id_bits_possible(const struct rohc_comp_rfc3095_ctxt *const ctxt,
                                                const size_t max_ip_id_bits_nr)
{
	return (ctxt->tmp.nr_ip_id_bits2 <= max_ip_id_bits_nr);
}


/**
 * @brief How many IP headers are IPv4 headers with non-random IP-IDs ?
 *
 * @param ctxt  The generic decompression context
 * @return      The number of IPv4 headers with non-random IP-ID fields
 */
static inline size_t get_nr_ipv4_non_rnd(const struct rohc_comp_rfc3095_ctxt *const ctxt)
{
	size_t nr_ipv4_non_rnd = 0;

	/* outer IP header */
	if(ctxt->outer_ip_flags.version == IPV4 && ctxt->outer_ip_flags.info.v4.rnd != 1)
	{
		nr_ipv4_non_rnd++;
	}

	return nr_ipv4_non_rnd;
}


/**
 * @brief How many IP headers are IPv4 headers with non-random IP-IDs and some
 *        bits to transmit ?
 *
 * @param ctxt  The generic decompression context
 * @return      The number of IPv4 headers with non-random IP-ID fields and some
 *              bits to transmit
 */
static inline size_t get_nr_ipv4_non_rnd_with_bits(const struct rohc_comp_rfc3095_ctxt *const ctxt)
{
	size_t nr_ipv4_non_rnd_with_bits = 0;

	/* outer IP header */
	if(ctxt->outer_ip_flags.version == IPV4 &&
	   ctxt->outer_ip_flags.info.v4.rnd != 1 &&
	   ctxt->tmp.nr_ip_id_bits > 0)
	{
		nr_ipv4_non_rnd_with_bits++;
	}

	return nr_ipv4_non_rnd_with_bits;
}


#endif

