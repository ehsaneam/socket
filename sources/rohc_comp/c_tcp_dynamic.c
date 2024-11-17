/*
 * Copyright 2012,2013,2014,2015,2016 Didier Barvaux
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
 * @file   c_tcp_dynamic.c
 * @brief  Handle the dynamic chain of the TCP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include <stdio.h>
#include "c_tcp_dynamic.h"
#include "c_tcp_defines.h"
#include "rfc4996.h"
#include "ip_numbers.h"
#include "ip_protocol.h"

#include <assert.h>

static int tcp_code_dynamic_ipv4_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv4_hdr *const ipv4,
                                      const bool is_innermost,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


/**
 * @brief Code the dynamic part of an IR or IR-DYN packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param[out] parsed_len   The length of uncompressed data parsed
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
int tcp_code_dyn_part(struct rohc_comp_ctxt *const context,
                      const struct ip_packet *const ip,
                      uint8_t *const rohc_pkt,
                      const size_t rohc_pkt_max_len,
                      size_t *const parsed_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	ip_context_t *inner_ip_context = NULL;

	const uint8_t *remain_data = ip->data;
	size_t remain_len = ip->size;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	const struct ip_hdr *inner_ip_hdr = NULL;
	size_t ip_hdr_pos;
	int ret;

	/* there is at least one IP header otherwise it won't be the IP/TCP profile */
	assert(tcp_context->ip_contexts_nr > 0);

	/* add dynamic chain for both IR and IR-DYN packet */
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip_hdr = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_inner = !!(ip_hdr_pos + 1 == tcp_context->ip_contexts_nr);

		/* the last IP header is the innermost one */
		inner_ip_context = ip_context;
		inner_ip_hdr = (struct ip_hdr *) remain_data;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip_hdr->version);

		if(ip_hdr->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			ret = tcp_code_dynamic_ipv4_part(context, ip_context, ipv4, is_inner,
			                                 rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv4 base header part "
				               "of the dynamic chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u", ip_hdr->version);
			assert(0);
			goto error;
		}
	}

	/* handle TCP header */
	{
		const struct tcphdr *const tcp = (struct tcphdr *) remain_data;

		assert(remain_len >= sizeof(struct tcphdr));

		/* add TCP dynamic part */
		ret = tcp_code_dynamic_tcp_part(context, tcp, rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build the TCP header part of the "
			               "dynamic chain");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
#endif
		rohc_remain_len -= ret;

		/* skip TCP header and options */
		remain_data += (tcp->data_offset << 2);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		remain_len -= (tcp->data_offset << 2);
#endif
		*parsed_len = remain_data - ip->data;
	}

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		inner_ip_context->ctxt.v4.last_ip_id_behavior =
			inner_ip_context->ctxt.v4.ip_id_behavior;
		inner_ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(inner_ipv4->id);
		inner_ip_context->ctxt.v4.df = inner_ipv4->df;
		inner_ip_context->ctxt.vx.dscp = inner_ipv4->dscp;
	}
	else
	{
		rohc_comp_warn(context, "unexpected IP version %u", inner_ip_hdr->version);
		assert(0);
		goto error;
	}
	inner_ip_context->ctxt.vx.ttl_hopl = tcp_context->tmp.ttl_hopl;

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv4 header
 *
 * @param context         The compression context
 * @param ip_context      The specific IP compression context
 * @param ipv4            The IPv4 header
 * @param is_innermost    true if the IP header is the innermost of the packet,
 *                        false otherwise
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_ipv4_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv4_hdr *const ipv4,
                                      const bool is_innermost,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
{
	ipv4_dynamic1_t *const ipv4_dynamic1 = (ipv4_dynamic1_t *) rohc_data;
	size_t ipv4_dynamic_len = sizeof(ipv4_dynamic1_t);
	uint16_t ip_id;

	assert(ip_context->ctxt.vx.version == IPV4);

	if(rohc_max_len < ipv4_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv4 dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_dynamic_len, rohc_max_len);
		goto error;
	}

	/* IP-ID */
	ip_id = rohc_ntoh16(ipv4->id);
	rohc_comp_debug(context, "ip_id_behavior = %d, last IP-ID = 0x%04x, "
	                "IP-ID = 0x%04x", ip_context->ctxt.v4.ip_id_behavior,
	                ip_context->ctxt.v4.last_ip_id, ip_id);

	ipv4_dynamic1->reserved = 0;
	ipv4_dynamic1->df = ipv4->df;

	/* IP-ID behavior
	 * cf. RFC4996 page 60/61 ip_id_behavior_choice() and ip_id_enc_dyn() */
	if(is_innermost)
	{
		/* all behavior values possible */
		ipv4_dynamic1->ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;
	}
	else
	{
		/* only IP_ID_BEHAVIOR_RAND or IP_ID_BEHAVIOR_ZERO */
		if(ipv4->id == 0)
		{
			ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_ZERO;
		}
		else
		{
			ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_RAND;
		}
		/* TODO: should not update context there */
		ip_context->ctxt.v4.ip_id_behavior = ipv4_dynamic1->ip_id_behavior;
	}
	/* TODO: should not update context there */
	ip_context->ctxt.v4.last_ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;

	ipv4_dynamic1->dscp = ipv4->dscp;
	ipv4_dynamic1->ip_ecn_flags = ipv4->ecn;
	ipv4_dynamic1->ttl_hopl = ipv4->ttl;

	/* IP-ID itself
	 * cf. RFC4996 page 60/61 ip_id_enc_dyn() */
	if(ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
	{
		rohc_comp_debug(context, "ip_id_behavior = %d", ipv4_dynamic1->ip_id_behavior);
	}
	else
	{
		ipv4_dynamic2_t *const ipv4_dynamic2 = (ipv4_dynamic2_t *) rohc_data;

		ipv4_dynamic_len = sizeof(ipv4_dynamic2_t);
		if(rohc_max_len < ipv4_dynamic_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv4 dynamic part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv4_dynamic_len, rohc_max_len);
			goto error;
		}

		ipv4_dynamic2->ip_id = ipv4->id;
		rohc_comp_debug(context, "ip_id_behavior = %d, IP-ID = 0x%04x",
		                ipv4_dynamic1->ip_id_behavior, rohc_ntoh16(ipv4->id));
	}

	/* TODO: should not update context there */
	ip_context->ctxt.v4.dscp = ipv4->dscp;
	ip_context->ctxt.v4.ttl_hopl = ipv4->ttl;
	ip_context->ctxt.v4.df = ipv4->df;
	ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(ipv4->id);

	rohc_comp_dump_buf(context, "IPv4 dynamic part", rohc_data, ipv4_dynamic_len);

	return ipv4_dynamic_len;

error:
	return -1;
}

/**
 * @brief Build the dynamic part of the TCP header.
 *
 * \verbatim

 Dynamic part of TCP header:

TODO

\endverbatim
 *
 * @param context         The compression context
 * @param tcp             The TCP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	tcp_dynamic_t *const tcp_dynamic = (tcp_dynamic_t *) rohc_remain_data;
	size_t tcp_dynamic_len = sizeof(tcp_dynamic_t);

	int indicator;
	int ret;

	rohc_comp_debug(context, "TCP dynamic part (minimal length = %zd)",
	                tcp_dynamic_len);

	if(rohc_remain_len < tcp_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
		               "%zu bytes required at minimum, but only %zu bytes available",
		               tcp_dynamic_len, rohc_remain_len);
		goto error;
	}

	rohc_comp_debug(context, "TCP seq = 0x%04x, ack_seq = 0x%04x",
	                rohc_ntoh32(tcp->seq_num), rohc_ntoh32(tcp->ack_num));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d",
	                *(uint16_t*)(((uint8_t*)tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = 0x%04x, check = 0x%x, "
	                "urg_ptr = %d", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->checksum), rohc_ntoh16(tcp->urg_ptr));

	tcp_dynamic->ecn_used = tcp_context->ecn_used;
	tcp_dynamic->tcp_res_flags = tcp->res_flags;
	tcp_dynamic->tcp_ecn_flags = tcp->ecn_flags;
	tcp_dynamic->urg_flag = tcp->urg_flag;
	tcp_dynamic->ack_flag = tcp->ack_flag;
	tcp_dynamic->psh_flag = tcp->psh_flag;
	tcp_dynamic->rsf_flags = tcp->rsf_flags;
	tcp_dynamic->msn = rohc_hton16(tcp_context->msn);
	tcp_dynamic->seq_num = tcp->seq_num;

	rohc_remain_data += sizeof(tcp_dynamic_t);
	rohc_remain_len -= sizeof(tcp_dynamic_t);

	/* TODO: should not update context here */
	tcp_context->tcp_seq_num_change_count++;

	/* ack_zero flag and ACK number: always check for the ACK number value even
	 * if the ACK flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those bits
	 * will be ignored at reception */
	ret = c_zero_or_irreg32(tcp->ack_num, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode zero_or_irreg(ack_number)");
		goto error;
	}
	tcp_dynamic->ack_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "TCP ack_number %spresent",
	                tcp_dynamic->ack_zero ? "not " : "");

	/* enough room for encoded window and checksum? */
	if(rohc_remain_len < (sizeof(uint16_t) + sizeof(uint16_t)))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
		               "%zu bytes required for TCP window and checksum, but only "
		               "%zu bytes available", sizeof(uint16_t) + sizeof(uint16_t),
		               rohc_remain_len);
		goto error;
	}

	/* window */
	memcpy(rohc_remain_data, &tcp->window, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* checksum */
	memcpy(rohc_remain_data, &tcp->checksum, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* urp_zero flag and URG pointer: always check for the URG pointer value
	 * even if the URG flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those
	 * bits will be ignored at reception */
	ret = c_zero_or_irreg16(tcp->urg_ptr, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode zero_or_irreg(urg_ptr)");
		goto error;
	}
	tcp_dynamic->urp_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "TCP urg_ptr %spresent",
	                tcp_dynamic->urp_zero ? "not " : "");

	/* ack_stride */
	{
		const bool is_ack_stride_static =
			tcp_is_ack_stride_static(tcp_context->ack_stride,
			                         tcp_context->ack_num_scaling_nr);
		ret = c_static_or_irreg16(rohc_hton16(tcp_context->ack_stride),
		                          is_ack_stride_static,
		                          rohc_remain_data, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
			goto error;
		}
		tcp_dynamic->ack_stride_flag = indicator;
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "TCP ack_stride %spresent",
		                tcp_dynamic->ack_stride_flag ? "" : "not ");
	}

	rohc_comp_debug(context, "TCP no options!");

	/* see RFC4996, §6.3.3 : no XI items, PS = 0, m = 0 */
	if(rohc_remain_len < 1)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
						"1 byte required for empty list of TCP option, but only "
						"%zu bytes available", rohc_remain_len);
		goto error;
	}
	rohc_remain_data[0] = 0x00;
	rohc_remain_data++;
	rohc_remain_len--;

	rohc_comp_dump_buf(context, "TCP dynamic part", rohc_data,
	                   rohc_max_len - rohc_remain_len);

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}

