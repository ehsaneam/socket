/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
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
 * @file   d_tcp_static.c
 * @brief  Handle the static chain of the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "d_tcp_static.h"

#include "d_tcp_defines.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "ip_numbers.h"

#include <string.h>


static int tcp_parse_static_ip(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_tcp_extr_ip_bits *const ip_bits,
                               uint8_t *const nh_proto)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

static int tcp_parse_static_tcp(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const rohc_packet,
                                const size_t rohc_length,
                                struct rohc_tcp_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


/**
 * @brief Parse the static chain of the IR packet
 *
 * @param context          The decompression context
 * @param rohc_packet      The remaining part of the ROHC packet
 * @param rohc_length      The remaining length (in bytes) of the ROHC packet
 * @param[out] bits        The bits extracted from the static chain
 * @param[out] parsed_len  The length (in bytes) of static chain in case of success
 * @return                 true in the static chain was successfully parsed,
 *                         false if the ROHC packet was malformed
 */
bool tcp_parse_static_chain(const struct rohc_decomp_ctxt *const context,
                            const uint8_t *const rohc_packet,
                            const size_t rohc_length,
                            struct rohc_tcp_extr_bits *const bits,
                            size_t *const parsed_len)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t ip_hdrs_nr;
	uint8_t protocol;
	int ret;

	(*parsed_len) = 0;

	/* parse static IP part (IPv4/IPv6 headers and extension headers) */
	ip_hdrs_nr = 0;
	struct rohc_tcp_extr_ip_bits *const ip_bits = &(bits->ip[ip_hdrs_nr]);

	ret = tcp_parse_static_ip(context, remain_data, remain_len, ip_bits,
								&protocol);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
							"static part");
		goto error;
	}
	rohc_decomp_debug(context, "IPv%u static part is %d-byte length",
						ip_bits->version, ret);
	assert(remain_len >= ((size_t) ret));
	remain_data += ret;
	remain_len -= ret;
	(*parsed_len) += ret;
	ip_hdrs_nr++;

	bits->ip_nr = ip_hdrs_nr;

	/* parse TCP static part */
	ret = tcp_parse_static_tcp(context, remain_data, remain_len, bits);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP static "
		                 "part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP static part is %d-byte length", ret);
	assert(remain_len >= ((size_t) ret));
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
	remain_len -= ret;
#endif
	(*parsed_len) += ret;

	return true;

error:
	return false;
}


/**
 * @brief Decode the static IP header of the rohc packet.
 *
 * @param context       The decompression context
 * @param rohc_packet   The remaining part of the ROHC packet
 * @param rohc_length   The remaining length (in bytes) of the ROHC packet
 * @param[out] ip_bits  The bits extracted from the IP part of the static chain
 * @param[out] nh_proto The next header protocol of the last extension header
 * @return              The length of static IP header in case of success,
 *                      -1 if an error occurs
 */
static int tcp_parse_static_ip(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_tcp_extr_ip_bits *const ip_bits,
                               uint8_t *const nh_proto)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t read = 0;

	rohc_decomp_debug(context, "parse IP static part");

	/* at least 1 byte required to read the version flag */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "version flag of the IP static part");
		goto error;
	}

	/* parse IPv4 static part or IPv6 static part? */
	if(GET_BIT_7(remain_data) == 0)
	{
		const ipv4_static_t *const ipv4_static = (ipv4_static_t *) remain_data;

		rohc_decomp_debug(context, "  IPv4 static part");
		ip_bits->version = IPV4;

		if(remain_len < sizeof(ipv4_static_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
			                 "IPv4 static part");
			goto error;
		}

		ip_bits->proto = ipv4_static->protocol;
		ip_bits->proto_nr = 8;
		*nh_proto = ip_bits->proto;
		memcpy(ip_bits->saddr, &ipv4_static->src_addr, sizeof(uint32_t));
		ip_bits->saddr_nr = 32;
		memcpy(ip_bits->daddr, &ipv4_static->dst_addr, sizeof(uint32_t));
		ip_bits->daddr_nr = 32;

		/* IP extension headers not supported for IPv4 */
		ip_bits->opts_nr = 0;
		ip_bits->opts_len = 0;

		read += sizeof(ipv4_static_t);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		remain_data += sizeof(ipv4_static_t);
		remain_len -= sizeof(ipv4_static_t);
#endif
	}
	rohc_decomp_dump_buf(context, "IP static part", rohc_packet, read);

	return read;

error:
	return -1;
}

/**
 * @brief Decode the TCP static part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param rohc_packet  The remaining part of the ROHC packet
 * @param rohc_length  The remaining length (in bytes) of the ROHC packet
 * @param[out] bits    The bits extracted from the CO packet
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_static_tcp(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const rohc_packet,
                                const size_t rohc_length,
                                struct rohc_tcp_extr_bits *const bits)
{
	const tcp_static_t *tcp_static;

	assert(rohc_packet != NULL);

	rohc_decomp_debug(context, "parse TCP static part");

	/* check the minimal length to decode the TCP static part */
	if(rohc_length < sizeof(tcp_static_t))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_length);
		goto error;
	}
	rohc_decomp_dump_buf(context, "TCP static part", rohc_packet,
	                     sizeof(tcp_static_t));
	tcp_static = (tcp_static_t *) rohc_packet;

	/* TCP source port */
	bits->src_port = rohc_ntoh16(tcp_static->src_port);
	bits->src_port_nr = 16;
	rohc_decomp_debug(context, "TCP source port = %u", bits->src_port);

	/* TCP destination port */
	bits->dst_port = rohc_ntoh16(tcp_static->dst_port);
	bits->dst_port_nr = 16;
	rohc_decomp_debug(context, "TCP dest port = %u", bits->dst_port);

	/* number of bytes read from the packet */
	rohc_decomp_debug(context, "TCP static part is %zu-byte long",
	                  sizeof(tcp_static_t));
	return sizeof(tcp_static_t);

error:
	return -1;
}

