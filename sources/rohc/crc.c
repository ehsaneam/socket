/*
 * Copyright 2007,2008 CNES
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2009,2010 Thales Communications
 * Copyright 2007,2009,2010,2012,2013 Viveris Technologies
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
 * @file crc.c
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author FWX <rohc_team@dialine.fr>
 */

#include "crc.h"
#include "ip_numbers.h"
#include "ip_protocol.h"
#include "ipv4.h"
#include "udp.h"
#include "tcp.h"

#include <stdlib.h>
#include <assert.h>

/**
 * Prototypes of private functions
 */

static char rohc_crc_get_polynom(const rohc_crc_type_t crc_type)
	__attribute__((warn_unused_result));


static inline uint8_t crc_calc_8(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val,
                                 const uint8_t *const crc_table)
	__attribute__((nonnull(1, 4), warn_unused_result, pure));
static inline uint8_t crc_calc_7(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val,
                                 const uint8_t *const crc_table)
	__attribute__((nonnull(1, 4), warn_unused_result, pure));
static inline uint8_t crc_calc_3(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val,
                                 const uint8_t *const crc_table)
	__attribute__((nonnull(1, 4), warn_unused_result, pure));

/**
 * Public functions
 */


/**
 * @brief Initialize a CRC table given a 256-byte table and the CRC type to use
 *
 * @param table     IN/OUT: The 256-byte table to initialize
 * @param crc_type  The type of CRC to initialize the table for
 */
void rohc_crc_init_table(uint8_t *const table,
                         const rohc_crc_type_t crc_type)
{
	uint8_t crc;
	uint8_t polynom;
	int i;

	/* sanity check */
	assert(table != NULL);

	/* determine the polynom to use */
	polynom = rohc_crc_get_polynom(crc_type);

	/* fill the CRC table */
	for(i = 0; i < 256; i++)
	{
		int j;

		crc = i;

		for(j = 0; j < 8; j++)
		{
			if(crc & 1)
			{
				crc = (crc >> 1) ^ polynom;
			}
			else
			{
				crc = crc >> 1;
			}
		}

		table[i] = crc;
	}
}


/**
 * @brief Calculate the checksum for the given data.
 *
 * @param crc_type   The CRC type
 * @param data       The data to calculate the checksum on
 * @param length     The length of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The checksum
 */
uint8_t crc_calculate(const rohc_crc_type_t crc_type,
                      const uint8_t *const data,
                      const size_t length,
                      const uint8_t init_val,
                      const uint8_t *const crc_table)
{
	uint8_t crc;

	/* call the function that corresponds to the CRC type */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_8:
			crc = crc_calc_8(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_7:
			crc = crc_calc_7(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_3:
			crc = crc_calc_3(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_NONE:
		default:
			/* undefined CRC type, should not happen */
			assert(0);
			crc = 0;
			break;
	}

	return crc;
}

/**
 * @brief Compute the CRC-STATIC part of an IP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-2, 7-10, 13-20 in original IPv4 header
 *    - bytes 1-4, 7-40 in original IPv6 header
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
uint8_t compute_crc_static(const uint8_t *const outer_ip,
                           const uint8_t *const inner_ip,
                           const uint8_t *const next_header __attribute__((unused)),
                           const rohc_crc_type_t crc_type,
                           const uint8_t init_val,
                           const uint8_t *const crc_table)
{
	const struct ip_hdr *const outer_ip_hdr = (struct ip_hdr *) outer_ip;
	uint8_t crc = init_val;

	assert(inner_ip==NULL || inner_ip!=NULL);

	/* first IPv4 header */
	if(outer_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) outer_ip;

		/* bytes 1-2 (Version, Header length, TOS) */
		crc = crc_calculate(crc_type, (uint8_t *)(ip_hdr), 2,
		                    crc, crc_table);
		/* bytes 7-10 (Flags, Fragment Offset, TTL, Protocol) */
		crc = crc_calculate(crc_type, (uint8_t *)(&ip_hdr->frag_off), 4,
		                    crc, crc_table);
		/* bytes 13-20 (Source Address, Destination Address) */
		crc = crc_calculate(crc_type, (uint8_t *)(&ip_hdr->saddr), 8,
		                    crc, crc_table);
	}

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an IP header
 *
 * Concerned fields are:
 *   - bytes 3-4, 5-6, 11-12 in original IPv4 header
 *   - bytes 5-6 in original IPv6 header
 *
 * @param outer_ip    The outer IP packet
 * @param inner_ip    The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
uint8_t compute_crc_dynamic(const uint8_t *const outer_ip,
                            const uint8_t *const inner_ip,
                            const uint8_t *const next_header __attribute__((unused)),
                            const rohc_crc_type_t crc_type,
                            const uint8_t init_val,
                            const uint8_t *const crc_table)
{
	const struct ip_hdr *const outer_ip_hdr = (struct ip_hdr *) outer_ip;
	uint8_t crc = init_val;
	assert(inner_ip==NULL || inner_ip!=NULL);
	/* first IPv4 header */
	if(outer_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) outer_ip;
		/* bytes 3-6 (Total Length, Identification) */
		crc = crc_calculate(crc_type, (uint8_t *)(&ip_hdr->tot_len), 4,
		                    crc, crc_table);
		/* bytes 11-12 (Header Checksum) */
		crc = crc_calculate(crc_type, (uint8_t *)(&ip_hdr->check), 2,
		                    crc, crc_table);
	}

	return crc;
}

/**
 * @brief Get the polynom for the given CRC type
 *
 * @param crc_type The CRC type
 * @return         The polynom for the requested CRC type
 */
static char rohc_crc_get_polynom(const rohc_crc_type_t crc_type)
{
	char polynom;

	/* determine the polynom for CRC */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_3:
			polynom = 0x6;
			break;
		case ROHC_CRC_TYPE_7:
			polynom = 0x79;
			break;
		case ROHC_CRC_TYPE_8:
			polynom = 0xe0;
			break;
		case ROHC_CRC_TYPE_NONE:
		default:
			/* unknown CRC type, should not happen */
#ifndef __clang_analyzer__ /* silent warning about value never read */
			polynom = 0x00;
#endif
			assert(0);
	}

	return polynom;
}

/**
 * @brief Optimized CRC-8 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline uint8_t crc_calc_8(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val,
                                 const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	size_t i;

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ crc];
	}

	return crc;
}


/**
 * @brief Optimized CRC-7 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline uint8_t crc_calc_7(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val,
                                 const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	size_t i;

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ (crc & 127)];
	}

	return crc;
}


/**
 * @brief Optimized CRC-3 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline uint8_t crc_calc_3(const uint8_t *const buf,
                                 const size_t size,
                                 const uint8_t init_val,
                                 const uint8_t *const crc_table)
{
	uint8_t crc = init_val;
	size_t i;

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ (crc & 7)];
	}

	return crc;
}

