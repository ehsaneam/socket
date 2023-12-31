/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012 Viveris Technologies
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
 * @file rohc.h
 * @brief ROHC common definitions and routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_H
#define ROHC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <stddef.h>


/** Macro that handles deprecated declarations gracefully */
#if defined __GNUC__ && \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
	/* __attribute__((deprecated(msg))) is supported by GCC 4.5 and later */
	#define ROHC_DEPRECATED(msg) __attribute__((deprecated(msg)))
#elif defined __GNUC__ && \
      (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
	/* __attribute__((deprecated)) is supported by GCC 3.1 and later */
	#define ROHC_DEPRECATED(msg) __attribute__((deprecated))
#else
	/* no support */
	#define ROHC_DEPRECATED(msg)
#endif


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
#  define ROHC_EXPORT __declspec(dllexport)
#else
#  define ROHC_EXPORT
#endif


/**
 * @brief The Ethertype assigned to the ROHC protocol by the IEEE
 *
 * @see http://standards.ieee.org/regauth/ethertype/eth.txt
 *
 * @ingroup rohc
 */
#define ROHC_ETHERTYPE  0x22f1


/**
 * @brief The status code of several functions in the library API
 *
 * @ingroup rohc
 */
typedef enum
{
	/** The action was successful */
	ROHC_STATUS_OK                = 0,
	/** The action failed due to a malformed packet */
	ROHC_STATUS_MALFORMED         = 2,
	/** The action failed because no matching context exists */
	ROHC_STATUS_NO_CONTEXT        = 3,
	/** The action failed due to a CRC failure */
	ROHC_STATUS_BAD_CRC           = 4,
	/** The action failed because output buffer is too small */
	ROHC_STATUS_OUTPUT_TOO_SMALL  = 5,
	/** The action encountered an undefined problem */
	ROHC_STATUS_ERROR             = 6,

} rohc_status_t;


/**
 * @brief ROHC operation modes
 *
 * The different ROHC operation modes as defined in section 4.4 of RFC 3095.
 *
 * If you add a new operation mode, please also add the corresponding textual
 * description in \ref rohc_get_mode_descr.
 *
 * @ingroup rohc
 *
 * @see rohc_get_mode_descr
 */
typedef enum
{
	/** Unknown operational mode */
	ROHC_UNKNOWN_MODE = 0,
	/** The Unidirectional mode (U-mode) */
	ROHC_U_MODE = 1,
} rohc_mode_t;

/**
 * @brief The maximum value for small CIDs
 *
 * @ingroup rohc
 *
 * @see rohc_comp_new
 * @see rohc_c_set_max_cid
 * @see rohc_decomp_set_max_cid
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \snippet simple_rohc_program.c create ROHC compressor
 */
#define ROHC_SMALL_CID_MAX  15U


/**
 * @brief The different types of Context IDs (CID)
 *
 * The different types of Context IDs (CID) a ROHC compressor or a ROHC
 * decompressor may use.
 *
 * Possible values are:
 *  \li \ref ROHC_SMALL_CID : small CID means that a ROHC compressor or a ROHC
 *      decompressor may identify contexts with IDs in the range
 *      [0, \ref ROHC_SMALL_CID_MAX ], ie. it may uniquely identify at
 *      most \e ROHC_SMALL_CID_MAX + 1 streams.
 *
 * In short, you choose the CID type in function of the number of simultaneous
 * streams you have to compress efficiently.
 *
 *
 * @ingroup rohc
 */
typedef enum
{
	/**
	 * @brief The context uses small CID
	 *
	 * CID value shall be in the range [0, \ref ROHC_SMALL_CID_MAX].
	 */
	ROHC_SMALL_CID,

} rohc_cid_type_t;


/** A ROHC Context ID (CID) */
typedef size_t rohc_cid_t;


/*
 * ROHC profiles numbers allocated by the IANA (see 8 in the RFC 3095):
 */

/**
 * @brief The different ROHC compression/decompression profiles
 *
 * If you add a new compression/decompression profile, please also add the
 * corresponding textual description in \ref rohc_get_profile_descr.
 *
 * @ingroup rohc
 *
 * @see rohc_get_profile_descr
 */
typedef enum
{
	/** The ROHC Uncompressed profile (RFC 3095, section 5.10) */
	ROHC_PROFILE_UNCOMPRESSED = 0x0000,
	/** The ROHC UDP profile (RFC 3095, section 5.11) */
	ROHC_PROFILE_UDP          = 0x0002,
	/** The ROHC IP-only profile (RFC 3843, section 5) */
	ROHC_PROFILE_IP           = 0x0004,
	/** The ROHC TCP profile (RFC 4996) */
	ROHC_PROFILE_TCP          = 0x0006,

	ROHC_PROFILE_MAX          = 0x0009,

} rohc_profile_t;

/*
 * Prototypes of public functions
 */

char * ROHC_EXPORT rohc_version(void)
	__attribute__((warn_unused_result, const));

const char * ROHC_EXPORT rohc_strerror(const rohc_status_t status)
	__attribute__((warn_unused_result, const));

const char * ROHC_EXPORT rohc_get_mode_descr(const rohc_mode_t mode)
	__attribute__((warn_unused_result, const));

const char * ROHC_EXPORT rohc_get_profile_descr(const rohc_profile_t profile)
	__attribute__((warn_unused_result, const));

#undef ROHC_EXPORT /* do not pollute outside this header */

#ifdef __cplusplus
}
#endif

#endif /* ROHC_H */

