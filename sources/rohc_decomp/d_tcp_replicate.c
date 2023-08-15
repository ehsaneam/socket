/*
 * Copyright 2016 Didier Barvaux
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
 * @file   d_tcp_replicate.c
 * @brief  Handle the replicate chain of the TCP decompression profile
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_tcp_replicate.h"

#include "d_tcp_defines.h"
#include "rfc4996.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "ip_numbers.h"

#ifndef __KERNEL__
#  include <string.h>
#endif


static int tcp_parse_replicate_ip(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *const rohc_packet,
                                  const size_t rohc_length,
                                  struct rohc_tcp_extr_ip_bits *const ip_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int tcp_parse_replicate_tcp(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const rohc_packet,
                                   const size_t rohc_length,
                                   struct rohc_tcp_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


/**
 * @brief Parse the replicate chain of the IR-CR packet
 *
 * @param context          The decompression context
 * @param rohc_packet      The remaining part of the ROHC packet
 * @param rohc_length      The remaining length (in bytes) of the ROHC packet
 * @param[out] bits        The bits extracted from the replicate chain
 * @param[out] parsed_len  The length (in bytes) of replicate chain in case of success
 * @return                 true in the replicate chain was successfully parsed,
 *                         false if the ROHC packet was malformed
 */
bool tcp_parse_replicate_chain(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_tcp_extr_bits *const bits,
                               size_t *const parsed_len)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t ip_hdrs_nr;
	int ret;

	(*parsed_len) = 0;

	/* parse replicate IP part (IPv4/IPv6 headers and extension headers) */
	assert(bits->ip_nr > 0);
	for(ip_hdrs_nr = 0; ip_hdrs_nr < bits->ip_nr; ip_hdrs_nr++)
	{
		struct rohc_tcp_extr_ip_bits *const ip_bits = &(bits->ip[ip_hdrs_nr]);

		ret = tcp_parse_replicate_ip(context, remain_data, remain_len, ip_bits);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "replicate part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u replicate part is %d-byte length",
		                  ip_bits->version, ret);
		assert(remain_len >= ((size_t) ret));
		remain_data += ret;
		remain_len -= ret;
		(*parsed_len) += ret;
	}

	/* parse TCP replicate part */
	ret = tcp_parse_replicate_tcp(context, remain_data, remain_len, bits);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP replicate "
		                 "part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP replicate part is %d-byte length", ret);
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
 * @brief Decode the replicate IP header of the rohc packet.
 *
 * @param context       The decompression context
 * @param rohc_packet   The remaining part of the ROHC packet
 * @param rohc_length   The remaining length (in bytes) of the ROHC packet
 * @param[out] ip_bits  The bits extracted from the IP part of the replicate chain
 * @return              The length of replicate IP header in case of success,
 *                      -1 if an error occurs
 */
static int tcp_parse_replicate_ip(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *const rohc_packet,
                                  const size_t rohc_length,
                                  struct rohc_tcp_extr_ip_bits *const ip_bits)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t size = 0;

	rohc_decomp_debug(context, "parse IP replicate part");

	if(ip_bits->version == IPV4)
	{
		const ipv4_replicate_t *const ipv4_replicate =
			(ipv4_replicate_t *) remain_data;

		if(remain_len < sizeof(ipv4_replicate_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv4 replicate part");
			goto error;
		}

		if(ipv4_replicate->reserved != 0)
		{
			rohc_decomp_debug(context, "IPv4 replicate part: reserved field is 0x%x"
			                  "instead of 0x0", ipv4_replicate->reserved);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}

		ip_bits->id_behavior = ipv4_replicate->ip_id_behavior;
		ip_bits->id_behavior_nr = 2;
		rohc_decomp_debug(context, "ip_id_behavior = %d", ip_bits->id_behavior);
		ip_bits->df = ipv4_replicate->df;
		ip_bits->df_nr = 1;
		ip_bits->dscp_bits = ipv4_replicate->dscp;
		ip_bits->dscp_bits_nr = 6;
		ip_bits->ecn_flags_bits = ipv4_replicate->ip_ecn_flags;
		ip_bits->ecn_flags_bits_nr = 2;
		rohc_decomp_debug(context, "DF = %d, DSCP = 0x%x, ip_ecn_flags = %d",
		                  ip_bits->df, ip_bits->dscp_bits, ip_bits->ecn_flags_bits);
		size += sizeof(ipv4_replicate_t);
		remain_data += sizeof(ipv4_replicate_t);
		remain_len -= sizeof(ipv4_replicate_t);

		/* IP-ID: cf RFC6846 ip_id_enc_dyn() */
		if(ipv4_replicate->ip_id_behavior != IP_ID_BEHAVIOR_ZERO)
		{
			const uint16_t *const replicate_ip_id = (uint16_t *) remain_data;

			if(remain_len < sizeof(uint16_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "IP-ID in IPv4 replicate part");
				goto error;
			}

			ip_bits->id.bits = rohc_ntoh16(*replicate_ip_id);
			ip_bits->id.bits_nr = 16;
			rohc_decomp_debug(context, "IP-ID = 0x%04x", ip_bits->id.bits);

			size += sizeof(uint16_t);
			remain_data += sizeof(uint16_t);
			remain_len -= sizeof(uint16_t);
		}

		/* TTL/HL */
		if(ipv4_replicate->ttl_flag == 1)
		{
			if(remain_len < sizeof(uint8_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "TTL/HL in IPv4 replicate part");
				goto error;
			}

			ip_bits->ttl_hl.bits = remain_data[0];
			ip_bits->ttl_hl.bits_nr = 8;
			rohc_decomp_debug(context, "ttl_hopl = 0x%x", ip_bits->ttl_hl.bits);

			size += sizeof(uint8_t);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_data += sizeof(uint8_t);
			remain_len -= sizeof(uint8_t);
#endif
		}
	}
	
	rohc_decomp_dump_buf(context, "IP replicate part", rohc_packet, size);

	return size;

error:
	return -1;
}

/**
 * @brief Decode the TCP replicate part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param rohc_packet  The remaining part of the ROHC packet
 * @param rohc_length  The remaining length (in bytes) of the ROHC packet
 * @param[out] bits    The bits extracted from the CO packet
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_replicate_tcp(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const rohc_packet,
                                   const size_t rohc_length,
                                   struct rohc_tcp_extr_bits *const bits)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	const tcp_replicate_t *tcp_replicate;
	int ret;

	rohc_decomp_debug(context, "parse TCP replicate part");

	/* check the minimal length to decode the TCP replicate part */
	if(remain_len < sizeof(tcp_replicate_t))
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "fixed-size TCP replicate part", remain_len,
		                 sizeof(tcp_replicate_t));
		goto error;
	}
	rohc_decomp_dump_buf(context, "TCP replicate part", remain_data,
	                     sizeof(tcp_replicate_t));
	tcp_replicate = (tcp_replicate_t *) rohc_packet;
	remain_data += sizeof(tcp_replicate_t);
	remain_len -= sizeof(tcp_replicate_t);

	/* check that reserved field is set to 0 */
	if(tcp_replicate->reserved != 0)
	{
		rohc_decomp_debug(context, "TCP replicate part: reserved field is %u"
		                  "instead of 0", tcp_replicate->reserved);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	/* retrieve the TCP flags from the TCP replicate part */
	rohc_decomp_debug(context, "TCP URG = %d, ACK = %u, PSH = %u, rsf_flags = %u, "
	                  "ecn_used = %u", tcp_replicate->urg_flag,
	                  tcp_replicate->ack_flag, tcp_replicate->psh_flag,
	                  tcp_replicate->rsf_flags, tcp_replicate->ecn_used);
	bits->urg_flag_bits = tcp_replicate->urg_flag;
	bits->urg_flag_bits_nr = 1;
	bits->ack_flag_bits = tcp_replicate->ack_flag;
	bits->ack_flag_bits_nr = 1;
	bits->psh_flag_bits = tcp_replicate->psh_flag;
	bits->psh_flag_bits_nr = 1;
	bits->rsf_flags_bits = tcp_replicate->rsf_flags;
	bits->rsf_flags_bits_nr = 2;
	bits->ecn_used_bits = tcp_replicate->ecn_used;
	bits->ecn_used_bits_nr = 1;

	/* retrieve the MSN from the TCP replicate part */
	bits->msn.bits = rohc_ntoh16(tcp_replicate->msn);
	bits->msn.bits_nr = 16;
	rohc_decomp_debug(context, "%zu bits of MSN 0x%04x",
	                  bits->msn.bits_nr, bits->msn.bits);

	/* retrieve the TCP sequence number from the TCP replicate part */
	bits->seq.bits = rohc_ntoh32(tcp_replicate->seq_num);
	bits->seq.bits_nr = 32;
	rohc_decomp_debug(context, "%zu bits of TCP sequence number 0x%08x",
	                  bits->seq.bits_nr, bits->seq.bits);

	/* TCP source port */
	if(tcp_replicate->src_port_presence == ROHC_TCP_PORT_IRREGULAR)
	{
		const uint16_t *const tcp_replicate_src_port = (uint16_t *) remain_data;

		if(remain_len < sizeof(uint16_t))
		{
			rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
			                 "available while at least %zu bytes required for the "
			                 "irregular TCP source port", remain_len, sizeof(uint16_t));
			goto error;
		}
		bits->src_port = rohc_ntoh16(*tcp_replicate_src_port);
		bits->src_port_nr = 16;
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	else if(tcp_replicate->src_port_presence == ROHC_TCP_PORT_LSB8)
	{
		/* TODO: handle LSB8 encoding for port_replicate() */
		rohc_decomp_warn(context, "LSB8 encoding is not supported yet for port_replicate()");
		goto error;
	}
	else if(tcp_replicate->src_port_presence != ROHC_TCP_PORT_STATIC)
	{
		rohc_decomp_warn(context, "src_port_presence is %u but only 0, 1 and 2 are "
		                 "allowed for the flags of port_replicate()",
		                 tcp_replicate->src_port_presence);
		goto error;
	}
	rohc_decomp_debug(context, "TCP source port = %u", bits->src_port);

	/* TCP destination port */
	if(tcp_replicate->dst_port_presence == ROHC_TCP_PORT_IRREGULAR)
	{
		const uint16_t *const tcp_replicate_dst_port = (uint16_t *) remain_data;

		if(remain_len < sizeof(uint16_t))
		{
			rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
			                 "available while at least %zu bytes required for the "
			                 "irregular TCP destination port", remain_len,
			                 sizeof(uint16_t));
			goto error;
		}
		bits->dst_port = rohc_ntoh16(*tcp_replicate_dst_port);
		bits->dst_port_nr = 16;
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	else if(tcp_replicate->dst_port_presence == ROHC_TCP_PORT_LSB8)
	{
		/* TODO: handle LSB8 encoding for port_replicate() */
		rohc_decomp_warn(context, "LSB8 encoding is not supported yet for port_replicate()");
		goto error;
	}
	else if(tcp_replicate->dst_port_presence != ROHC_TCP_PORT_STATIC)
	{
		rohc_decomp_warn(context, "dst_port_presence is %u but only 0, 1 and 2 are "
		                 "allowed for the flags of port_replicate()",
		                 tcp_replicate->dst_port_presence);
		goto error;
	}
	rohc_decomp_debug(context, "TCP destination port = %u", bits->dst_port);

	/* window */
	ret = d_static_or_irreg16(remain_data, remain_len, tcp_replicate->window_presence,
	                          &bits->window);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(window) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %zu bits of TCP window encoded on "
	                  "%d bytes", bits->window.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* URG pointer */
	ret = d_static_or_irreg16(remain_data, remain_len, tcp_replicate->urp_presence,
	                          &bits->urg_ptr);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(urg_ptr) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %zu bits of TCP URG Pointer encoded on "
	                  "%d bytes", bits->urg_ptr.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* ACK number */
	ret = d_static_or_irreg32(remain_data, remain_len, tcp_replicate->ack_presence,
	                          &bits->ack);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(ack_number) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %zu bits of TCP ACK number encoded on "
	                  "%d bytes", bits->ack.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* ecn_padding + tcp_res_flags + tcp_ecn_flags */
	if(tcp_replicate->ecn_used)
	{
		if(remain_len < sizeof(uint8_t))
		{
			rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
			                 "available while at least %zu bytes required for "
			                 "ecn_padding + tcp_res_flags + tcp_ecn_flags",
			                 remain_len, sizeof(uint8_t));
			goto error;
		}
		if(GET_BIT_6_7(remain_data) != 0)
		{
			rohc_decomp_debug(context, "TCP replicate part: reserved field along "
			                  "RES and ECN flags is %u instead of 0",
			                  GET_BIT_6_7(remain_data));
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}
		bits->res_flags_bits = GET_BIT_2_5(remain_data);
		bits->res_flags_bits_nr = 4;
		bits->ecn_flags_bits = GET_BIT_0_1(remain_data);
		bits->ecn_flags_bits_nr = 2;
		remain_data++;
		remain_len--;
		rohc_decomp_debug(context, "TCP RES and ECM flags %spresent",
		                  tcp_replicate->ecn_used ? "" : "not ");
	}

	/* checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "checksum", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&(bits->tcp_check), remain_data, sizeof(uint16_t));
	bits->tcp_check = rohc_ntoh16(bits->tcp_check);
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP checksum = 0x%04x", bits->tcp_check);

	/* ACK stride */
	ret = d_static_or_irreg16(remain_data, remain_len, tcp_replicate->ack_stride_flag,
	                          &bits->ack_stride);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(ack_stride) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %zu bits of ACK stride encoded on "
	                  "%d bytes", bits->ack_stride.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	assert(remain_len <= rohc_length);
	rohc_decomp_dump_buf(context, "TCP replicate part",
	                     rohc_packet, rohc_length - remain_len);

	return (rohc_length - remain_len);

error:
	return -1;
}

