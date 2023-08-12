/*
 * Copyright 2013,2014 Didier Barvaux
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
 * @file   ip_numbers.c
 * @brief  Defines the IPv4 protocol numbers
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "ip_numbers.h"

/**
 * @brief Give a description for the given IP protocol
 *
 * @param protocol  The IP protocol to get a description for
 * @return          A string that describes the given IP protocol
 */
const char * rohc_get_ip_proto_descr(const uint8_t protocol)
{
	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:
			return "Hop-by-Hop option";
		case ROHC_IPPROTO_TCP:
			return "TCP";
		case ROHC_IPPROTO_UDP:
			return "UDP";
		case ROHC_IPPROTO_AH:
			return "AH";
		case ROHC_IPPROTO_MINE:
			return "MINE";
		case ROHC_IPPROTO_MOBILITY:
			return "Mobility option";
		case ROHC_IPPROTO_HIP:
			return "HIP";
		case ROHC_IPPROTO_SHIM:
			return "SHIM";
		case ROHC_IPPROTO_RESERVED1:
			return "reserved 1";
		case ROHC_IPPROTO_RESERVED2:
			return "reserved 2";
		case ROHC_IPPROTO_MAX:
		default:
			return "unknown IP protocol";
	}
}

