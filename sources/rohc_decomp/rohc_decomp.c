/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
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
 * @file rohc_decomp.c
 * @brief ROHC decompression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_decomp  The ROHC decompression API
 *
 * The decompression API of the ROHC library allows a program to decompress
 * some ROHC packets into uncompressed packets.
 *
 * The program shall first create a decompressor context and configure it. It
 * then may decompress as many packets as needed. When done, the ROHC
 * decompressor context shall be destroyed.
 */

#include "rohc_decomp.h"
#include "rohc_decomp_internals.h"
#include "rohc_traces_internal.h"
#include "rohc_time_internal.h"
#include "rohc_utils.h"
#include "rohc_bit_ops.h"
#include "rohc_debug.h"
#include "rohc_add_cid.h"
#include "rohc_decomp_detect_packet.h"
#include "crc.h"

#include <string.h>
#include <stdarg.h>
#include <assert.h>


extern const struct rohc_decomp_profile d_uncomp_profile;
extern const struct rohc_decomp_profile d_udp_profile;
extern const struct rohc_decomp_profile d_ip_profile;
extern const struct rohc_decomp_profile d_tcp_profile;


/**
 * @brief The decompression parts of the ROHC profiles.
 */
static const struct rohc_decomp_profile *const rohc_decomp_profiles[D_NUM_PROFILES] =
{
	&d_uncomp_profile,
	&d_udp_profile,
	&d_ip_profile,
	&d_tcp_profile,
};


/*
 * Definitions of private structures
 */

/**
 * @brief The stream informations about a decompressed packet
 *
 * To be able to send some feedback to the compressor, the decompressor shall
 * (aside the decompression status itself) collect some informations about
 * the packet being decompressed:
 *  \li the Context ID (CID) of the packet (even if context was not found)
 *  \li the CID type of the channel
 *  \li the ID of the decompression profile
 *  \li if context was found, the context mode
 *  \li if context was found, the context state
 *  \li if context was found, the SN (LSB bits) of the latest successfully
 *      decompressed packet
 *  \li the packet type if available
 */
struct rohc_decomp_stream
{
	rohc_cid_type_t cid_type;  /**< The CID type of the channel */
	bool cid_found;            /**< Whether the CID of the packet was found or not */
	rohc_cid_t cid;            /**< The CID of the packet */
	bool context_found;        /**< Whether the context was found or not */
	struct rohc_decomp_ctxt *context; /**< The decompression context, if found */
	rohc_profile_t profile_id; /**< The decompression profile (ROHC_PROFILE_GENERAL
	                                if not identified) */
	rohc_mode_t mode;          /**< The context mode (if context found) */
	bool do_change_mode;       /**< The context mode shall be advertised */
	rohc_decomp_state_t state; /**< The context state (if context found) */
	uint32_t sn_bits;          /**< The SN LSB bits (if context found) */
	size_t sn_bits_nr;         /**< The number of SN LSB bits (if context found) */
	rohc_packet_t packet_type; /**< The type of the decompressed packet */
	bool crc_failed;           /**< Whether the packet failed the CRC check or not */
};


/*
 * Prototypes of private functions
 */

static bool rohc_decomp_create_contexts(struct rohc_decomp *const decomp,
                                        const rohc_cid_t max_cid)
	__attribute__((nonnull(1), warn_unused_result));

static const struct rohc_decomp_profile *
	find_profile(const struct rohc_decomp *const decomp,
	             const rohc_profile_t profile_id)
	__attribute__((warn_unused_result));

static struct rohc_decomp_ctxt * context_create(struct rohc_decomp *decomp,
                                                const rohc_cid_t cid,
                                                const struct rohc_decomp_profile *const profile,
                                                const struct rohc_ts arrival_time);
static struct rohc_decomp_ctxt * find_context(const struct rohc_decomp *const decomp,
                                              const size_t cid)
	__attribute__((nonnull(1), warn_unused_result));
static void context_free(struct rohc_decomp_ctxt *const context)
	__attribute__((nonnull(1)));

static rohc_status_t d_decode_header(struct rohc_decomp *decomp,
                                     const struct rohc_buf rohc_packet,
                                     struct rohc_buf *const uncomp_packet,
                                     struct rohc_buf *const rcvd_feedback,
                                     struct rohc_decomp_stream *const stream)
	__attribute__((nonnull(1, 3, 5), warn_unused_result));

static bool rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                   const uint8_t *packet,
                                   unsigned int len,
                                   rohc_cid_t *const cid,
                                   size_t *const add_cid_len,
                                   size_t *const large_cid_len)
	__attribute__((nonnull(1, 2, 4, 5, 6), warn_unused_result));

static void rohc_decomp_parse_padding(const struct rohc_decomp *const decomp,
                                      struct rohc_buf *const packet)
	__attribute__((nonnull(1, 2)));

static rohc_status_t rohc_decomp_find_context(struct rohc_decomp *const decomp,
                                              const uint8_t *const packet,
                                              const size_t packet_len,
                                              const rohc_cid_type_t cid,
                                              const size_t large_cid_len,
                                              const struct rohc_ts arrival_time,
                                              rohc_profile_t *const profile_id,
                                              struct rohc_decomp_ctxt **const context,
                                              bool *const context_created)
	__attribute__((warn_unused_result, nonnull(1, 2, 7, 8, 9)));

static rohc_status_t rohc_decomp_decode_pkt(struct rohc_decomp *const decomp,
                                            struct rohc_decomp_ctxt *const context,
                                            const struct rohc_buf rohc_packet,
                                            const size_t add_cid_len,
                                            const size_t large_cid_len,
                                            struct rohc_buf *const uncomp_packet,
                                            rohc_packet_t *const packet_type,
                                            bool *const do_change_mode)
	__attribute__((warn_unused_result, nonnull(1, 2, 6, 7, 8)));

static bool rohc_decomp_check_ir_crc(const struct rohc_decomp *const decomp,
                                     const struct rohc_decomp_ctxt *const context,
                                     const uint8_t *const rohc_hdr,
                                     const size_t rohc_hdr_len,
                                     const size_t add_cid_len,
                                     const size_t large_cid_len,
                                     const uint8_t crc_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void rohc_decomp_stats_add_success(struct rohc_decomp_ctxt *const context,
                                          const size_t comp_hdr_len,
                                          const size_t uncomp_hdr_len)
	__attribute__((nonnull(1)));

static void rohc_decomp_update_context(struct rohc_decomp_ctxt *const context,
                                       const void *const decoded_values,
                                       const size_t payload_len,
                                       const struct rohc_ts pkt_arrival_time,
                                       bool *const do_change_mode)
	__attribute__((nonnull(1, 2, 5)));

/* statistics-related functions */
static void rohc_decomp_reset_stats(struct rohc_decomp *const decomp)
	__attribute__((nonnull(1)));



/*
 * Public functions
 */


/**
 * @brief Find one decompression context thanks to its CID.
 *
 * @param decomp The ROHC decompressor
 * @param cid    The CID of the context to find out
 * @return       The context if found, NULL otherwise
 */
static struct rohc_decomp_ctxt * find_context(const struct rohc_decomp *const decomp,
                                              const rohc_cid_t cid)
{
	/* CID must be valid wrt MAX_CID */
	assert(cid <= decomp->medium.max_cid);
	return decomp->contexts[cid];
}


/**
 * @brief Create one new decompression context with profile specific data.
 *
 * @param decomp        The ROHC decompressor
 * @param cid           The CID of the new context
 * @param profile       The profile to be assigned with the new context
 * @param arrival_time  The time at which packet was received (0 if unknown,
 *                      or to disable time-related features in ROHC protocol)
 * @return              The new context if successful, NULL otherwise
 */
static struct rohc_decomp_ctxt * context_create(struct rohc_decomp *decomp,
                                                const rohc_cid_t cid,
                                                const struct rohc_decomp_profile *const profile,
                                                const struct rohc_ts arrival_time)
{
	struct rohc_decomp_ctxt *context;

	assert(decomp != NULL);
	assert(cid <= ROHC_SMALL_CID_MAX);
	assert(profile != NULL);

	/* allocate memory for the decompression context */
	context = (struct rohc_decomp_ctxt *) malloc(sizeof(struct rohc_decomp_ctxt));
	if(context == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "cannot allocate memory for the contexts");
		goto error;
	}

	/* record the CID */
	context->cid = cid;

	/* associate the decompressor with the context */
	context->decompressor = decomp;

	/* associate the decompression profile with the context */
	context->profile = profile;

	/* initialize mode and state */
	context->mode = ROHC_U_MODE;
	context->state = ROHC_DECOMP_STATE_NC;

	/* init the context for packet/context corrections upon CRC failures */
	/* at the beginning, no attempt to correct CRC failure */
	context->crc_corr.algo = ROHC_DECOMP_CRC_CORR_SN_NONE;
	context->crc_corr.counter = 0;
	/* arrival times for correction upon CRC failure */
	memset(context->crc_corr.arrival_times, 0,
	       sizeof(struct rohc_ts) * ROHC_MAX_ARRIVAL_TIMES);
	context->crc_corr.arrival_times_nr = 0;
	context->crc_corr.arrival_times_index = 0;

	/* init some statistics */
	context->num_recv_packets = 0;
	context->total_uncompressed_size = 0;
	context->total_compressed_size = 0;
	context->header_uncompressed_size = 0;
	context->header_compressed_size = 0;
	context->total_last_uncompressed_size = 0;
	context->total_last_compressed_size = 0;
	context->header_last_uncompressed_size = 0;
	context->header_last_compressed_size = 0;
	context->corrected_crc_failures = 0;
	context->corrected_sn_wraparounds = 0;
	context->corrected_wrong_sn_updates = 0;
	context->nr_lost_packets = 0;
	context->nr_misordered_packets = 0;
	context->is_duplicated = 0;

	context->first_used = arrival_time.sec;
	context->latest_used = arrival_time.sec;

	/* create the profile-specific parts of the decompression context (performed
	 * at the every end so that everything is initialized in context first) */
	if(!profile->new_context(context, &context->persist_ctxt, &context->volat_ctxt))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to initialize the profile-specific parts of the "
		             "decompression context");
		goto destroy_context;
	}

	/* decompressor got one more context (for a short moment, decompressor
	 * might have MAX_CID + 2 contexts) */
	assert(decomp->num_contexts_used <= (decomp->medium.max_cid + 1));
	decomp->num_contexts_used++;

	return context;

destroy_context:
	zfree(context);
error:
	return NULL;
}


/**
 * @brief Destroy one decompression context and the profile specific data
 *        associated with it.
 *
 * @param context  The context to destroy
 */
static void context_free(struct rohc_decomp_ctxt *const context)
{
	assert(context->decompressor != NULL);
	assert(context->profile != NULL);

	rohc_debug(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
	           "free context with CID %zu", context->cid);

	/* destroy the profile-specific data */
	context->profile->free_context(context->persist_ctxt, &context->volat_ctxt);

	/* decompressor got one more context */
	assert(context->decompressor->num_contexts_used > 0);
	context->decompressor->num_contexts_used--;

	/* destroy the context itself */
	free(context);
}


/**
 * @brief Create a new ROHC decompressor
 *
 * Create a new ROHC decompressor with the given type of CIDs, MAX_CID, and
 * operational mode.
 *
 * @param cid_type  The type of Context IDs (CID) that the ROHC decompressor
 *                  shall operate with.\n
 *                  Accepted values are:
 *                    \li \ref ROHC_SMALL_CID for small CIDs
 *                    \li \ref ROHC_LARGE_CID for large CIDs
 * @param max_cid   The maximum value that the ROHC decompressor should use
 *                  for context IDs (CID). As CIDs starts with value 0, the
 *                  number of contexts is \e max_cid + 1.\n
 *                  Accepted values are:
 *                    \li [0, \ref ROHC_SMALL_CID_MAX] if \e cid_type is
 *                        \ref ROHC_SMALL_CID
 *                    \li [0, \ref ROHC_LARGE_CID_MAX] if \e cid_type is
 *                        \ref ROHC_LARGE_CID
 * @param mode      The operational mode that the ROHC decompressor shall target.\n
 *                  Accepted values are:
 *                    \li \ref ROHC_U_MODE for the Unidirectional mode,
 *                        mode,
 *                    \li \ref ROHC_R_MODE for the Bidirectional Reliable mode
 *                        is not supported yet: specifying \ref ROHC_R_MODE is
 *                        an error.
 * @return          The created decompressor if successful,
 *                  NULL if creation failed
 *
 * @warning Don't forget to free decompressor memory with
 *          \ref rohc_decomp_free if rohc_decomp_new2 succeeded
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c create ROHC decompressor #1
 * \snippet example_rohc_decomp.c create ROHC decompressor #2
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c destroy ROHC decompressor
 *
 * @see rohc_decomp_free
 * @see rohc_decompress3
 * @see rohc_decomp_set_traces_cb2
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_disable_profiles
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_set_mrru
 * @see rohc_decomp_set_features
 */
struct rohc_decomp * rohc_decomp_new2(const rohc_cid_type_t cid_type,
                                      const rohc_cid_t max_cid,
                                      const rohc_mode_t mode)
{

	struct rohc_decomp *decomp;
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
	if(mode != ROHC_U_MODE)
	{
		/* unexpected operational mode */
		goto error;
	}

	/* allocate memory for the decompressor */
	decomp = (struct rohc_decomp *) malloc(sizeof(struct rohc_decomp));
	if(decomp == NULL)
	{
		goto error;
	}

	/* no trace callback during decompressor creation */
	decomp->trace_callback = NULL;
	decomp->trace_callback_priv = NULL;

	/* default feature set (empty for the moment) */
	decomp->features = ROHC_DECOMP_FEATURE_NONE;

	/* init decompressor medium */
	decomp->medium.cid_type = cid_type;
	decomp->medium.max_cid = max_cid;

	/* all decompression profiles are disabled by default */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		decomp->enabled_profiles[i] = false;
	}

	/* the operational mode the decompressor shall target for all its contexts */
	decomp->target_mode = mode;

	/* initialize the array of decompression contexts to its minimal value */
	decomp->contexts = NULL;
	decomp->num_contexts_used = 0;
	is_fine = rohc_decomp_create_contexts(decomp, decomp->medium.max_cid);
	if(!is_fine)
	{
		goto destroy_decomp;
	}
	decomp->last_context = NULL;

	/* init the tables for fast CRC computation */
	rohc_crc_init_table(decomp->crc_table_3, ROHC_CRC_TYPE_3);
	rohc_crc_init_table(decomp->crc_table_7, ROHC_CRC_TYPE_7);
	rohc_crc_init_table(decomp->crc_table_8, ROHC_CRC_TYPE_8);

	/* reset the decompressor statistics */
	rohc_decomp_reset_stats(decomp);

	return decomp;

destroy_decomp:
	free(decomp);
error:
	return NULL;
}


/**
 * @brief Destroy the given ROHC decompressor
 *
 * Destroy a ROHC decompressor that was successfully created with
 * \ref rohc_decomp_new2
 *
 * @param decomp  The decompressor to destroy
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c create ROHC decompressor #1
 * \snippet example_rohc_decomp.c create ROHC decompressor #2
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c destroy ROHC decompressor
 *
 * @see rohc_decomp_new2
 */
void rohc_decomp_free(struct rohc_decomp *const decomp)
{
	rohc_cid_t i;

	/* sanity check */
	if(decomp == NULL)
	{
		goto error;
	}
	assert(decomp->contexts != NULL);

	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "free ROHC decompressor");

	/* destroy all the contexts owned by the decompressor */
	for(i = 0; i <= decomp->medium.max_cid; i++)
	{
		if(decomp->contexts[i] != NULL)
		{
			context_free(decomp->contexts[i]);
		}
	}
	zfree(decomp->contexts);
	assert(decomp->num_contexts_used == 0);

	/* destroy the decompressor itself */
	free(decomp);

error:
	return;
}


/**
 * @brief Decompress the given ROHC packet into one uncompressed packet
 *
 * Decompress the given ROHC packet into an uncompressed packet. The
 * decompression always returns ROHC_OK in case of success. The caller shall
 * however be ready to handle several cases:
 *  \li the uncompressed packet \e uncomp_packet might be empty if the ROHC
 *      packet contained only feedback data or if the ROHC packet was not a
 *      final segment
 *  \li the received feedback \e rcvd_feedback might be empty if the ROHC
 *      packet doesn't contain at least one feedback item
 *
 * If \e feedback_send is not NULL, the decompression may return some feedback
 * information on it. In such a case, the caller is responsible to send it to
 * the compressor through any feedback channel.
 *
 * Time-related features in the ROHC protocol: set the \e rohc_packet.time
 * parameter to 0 if arrival time of the ROHC packet is unknown or to disable
 * the time-related features in the ROHC protocol.
 *
 * @param decomp              The ROHC decompressor
 * @param rohc_packet         The compressed packet to decompress
 * @param[out] uncomp_packet  The resulting uncompressed packet
 * @param[out] rcvd_feedback  The feedback received from the remote peer for
 *                            the same-side associated ROHC compressor through
 *                            the feedback channel:
 *                            \li If NULL, ignore the received feedback data
 *                            \li If not NULL, store the received feedback in
 *                                at the given address
 * @param[out] feedback_send  The feedback to be transmitted to the remote
 *                            compressor through the feedback channel:
 *                            \li If NULL, the decompression won't generate
 *                                feedback information for its compressor
 *                            \li If not NULL, may store the generated
 *                                feedback at the given address
 * @return                    Possible return values:
 *                            \li \ref ROHC_STATUS_OK if a decompressed packet
 *                                is returned
 *                            \li \ref ROHC_STATUS_NO_CONTEXT if no
 *                                 decompression context matches the CID
 *                                 stored in the given ROHC packet and the
 *                                 ROHC packet is not an IR packet
 *                            \li \ref ROHC_STATUS_OUTPUT_TOO_SMALL if the
 *                                output buffer is too small for the
 *                                compressed packet
 *                            \li \ref ROHC_STATUS_MALFORMED if the
 *                                decompression failed because the ROHC packet
 *                                is malformed
 *                            \li \ref ROHC_STATUS_BAD_CRC if the CRC detected
 *                                a transmission or decompression problem
 *                            \li \ref ROHC_STATUS_ERROR if another problem
 *                                occurred
 *
 * @ingroup rohc_decomp
 *
 * \par Example #1:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \snippet example_rohc_decomp.c define IP and ROHC packets
 * \code
	...
\endcode
 * \snippet example_rohc_decomp.c decompress ROHC packet #1
 * \snippet example_rohc_decomp.c decompress ROHC packet #2
 * \snippet example_rohc_decomp.c decompress ROHC packet #3
 *
 * @see rohc_decomp_set_mrru
 */
rohc_status_t rohc_decompress3(struct rohc_decomp *const decomp,
                               const struct rohc_buf rohc_packet,
                               struct rohc_buf *const uncomp_packet,
                               struct rohc_buf *const rcvd_feedback,
                               struct rohc_buf *const feedback_send)
{
	rohc_status_t status = ROHC_STATUS_ERROR; /* error status by default */
	struct rohc_decomp_stream stream;

	assert(feedback_send==NULL || feedback_send!=NULL);

	/* check inputs validity */
	if(decomp == NULL)
	{
		goto error;
	}
	if(rohc_buf_is_malformed(rohc_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is malformed");
		goto error;
	}
	if(rohc_buf_is_empty(rohc_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is empty");
		goto error;
	}
	if(uncomp_packet == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is NULL");
		goto error;
	}
	if(rohc_buf_is_malformed(*uncomp_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is malformed");
		goto error;
	}
	if(!rohc_buf_is_empty(*uncomp_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is not empty");
		goto error;
	}

	decomp->stats.received++;
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "decompress the %zu-byte packet #%lu", rohc_packet.len,
	           decomp->stats.received);

	/* print compressed bytes */
	if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
	{
		rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
		                 ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
		                 "compressed data, max 100 bytes", rohc_packet);
	}

	/* decode ROHC header */
	status = d_decode_header(decomp, rohc_packet, uncomp_packet, rcvd_feedback,
	                         &stream);

	/* handle mode transitions if context was found and it is still valid */
	if(stream.context != NULL)
	{
		if(stream.context->mode == ROHC_U_MODE)
		{
			if(decomp->target_mode == ROHC_U_MODE)
			{
				rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
				           "stay in U-mode as requested by user");
			}
		}
	}

	/* update statistics and send feedback if needed */
	if(status == ROHC_STATUS_OK)
	{
		/* print a trace to report success (the context may be NULL if packet
		 * was a feedback-only packet) */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
		           "packet decompression succeeded");

		/* do not update statistics and build positive feedback for feedback-only
		 * packets */
		if(uncomp_packet->len > 0)
		{
			/* update statistics */
			rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
			           "update decompressor and context statistics");
			assert(stream.context != NULL);
			stream.context->num_recv_packets++;
			stream.context->packet_type = stream.packet_type;
			stream.context->total_last_uncompressed_size = uncomp_packet->len;
			stream.context->total_uncompressed_size += uncomp_packet->len;
			stream.context->total_last_compressed_size = rohc_packet.len;
			stream.context->total_compressed_size += rohc_packet.len;
			decomp->stats.total_uncompressed_size += uncomp_packet->len;
			decomp->stats.total_compressed_size += rohc_packet.len;
		}
	}
	else /* packet failed to be decompressed */
	{
		/* in case of failure, users shall get an empty decompressed packet */
		uncomp_packet->len = 0;

		rohc_warning(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
		             "packet decompression failed: %s (%d)",
		             rohc_strerror(status), status);

		/* update statistics */
		if(stream.context != NULL)
		{
			stream.context->num_recv_packets++;
		}
		switch(status)
		{
			case ROHC_STATUS_MALFORMED:
			case ROHC_STATUS_OUTPUT_TOO_SMALL:
			case ROHC_STATUS_ERROR:
				decomp->stats.failed_decomp++;
				break;
			case ROHC_STATUS_NO_CONTEXT:
				decomp->stats.failed_no_context++;
				break;
			case ROHC_STATUS_BAD_CRC:
				decomp->stats.failed_crc++;
				break;
			case ROHC_STATUS_OK: /* success codes shall not happen */
			default:
				assert(0);
				status = ROHC_STATUS_ERROR;
				goto error;
		}
	}

error:
	return status;
}


/**
 * @brief Decompress the compressed headers.
 *
 * @param decomp              The ROHC decompressor
 * @param rohc_packet         The ROHC packet to decode
 * @param[out] uncomp_packet  The uncompressed packet
 * @param[out] rcvd_feedback  The feedback received from the remote peer for
 *                            the same-side associated ROHC compressor through
 *                            the feedback channel:
 *                            \li If NULL, ignore the received feedback data
 *                            \li If not NULL, store the received feedback in
 *                                at the given address
 * @param[out] stream         The informations about the decompressed stream,
 *                            required for sending feedback to compressor
 * @return                    Possible return values:
 *                            \li ROHC_STATUS_OK if packet is successfully
 *                                decoded,
 *                            \li ROHC_STATUS_NO_CONTEXT if no matching
 *                                context was found and packet cannot create
 *                                a new context (or failed to do so),
 *                            \li ROHC_STATUS_MALFORMED if packet is
 *                                malformed,
 *                            \li ROHC_STATUS_BAD_CRC if a CRC error occurs,
 *                            \li ROHC_STATUS_ERROR if another error occurs
 */
static rohc_status_t d_decode_header(struct rohc_decomp *decomp,
                                     const struct rohc_buf rohc_packet,
                                     struct rohc_buf *const uncomp_packet,
                                     struct rohc_buf *const rcvd_feedback,
                                     struct rohc_decomp_stream *const stream)
{
	const struct rohc_decomp_profile *profile;
	bool is_new_context = false;
	size_t add_cid_len;
	size_t large_cid_len;
	assert(rcvd_feedback==NULL || rcvd_feedback!=NULL);

	struct rohc_buf remain_rohc_data = rohc_packet;
	const uint8_t *walk;
	size_t remain_len;

	rohc_status_t status;

	/* at the beginning, context is not found yet but channel CID type is known */
	stream->profile_id = ROHC_PROFILE_GENERAL;
	stream->cid_type = decomp->medium.cid_type;
	stream->cid_found = false;
	stream->cid = SIZE_MAX;
	stream->context_found = false;
	stream->context = NULL;
	stream->mode = ROHC_UNKNOWN_MODE;
	stream->state = ROHC_DECOMP_STATE_UNKNOWN;
	stream->do_change_mode = false;
	stream->sn_bits = 0; /* must be set to 0 until we get some bits */
	stream->sn_bits_nr = 0;
	stream->packet_type = ROHC_PACKET_UNKNOWN;
	stream->crc_failed = false;

	/* empty ROHC packets are not considered as valid */
	if(remain_rohc_data.len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "ROHC packet too small (len = %zu, at least 1 byte "
		             "required)", remain_rohc_data.len);
		goto error_malformed;
	}

	/* skip padding bits if some are present */
	rohc_decomp_parse_padding(decomp, &remain_rohc_data);

	/* padding-only packets are not allowed according to RFC 3095, §5.2:
	 *   Padding is any number (zero or more) of padding octets.  Either of
	 *   Feedback or Header must be present. */
	if(remain_rohc_data.len == 0)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "padding-only packet is not allowed");
		goto error_malformed;
	}

	walk = rohc_buf_data(remain_rohc_data);
	remain_len = remain_rohc_data.len;

	/* is there some data after feedback? */
	if(remain_rohc_data.len == 0)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "feedback-only packet, stop decompression");
		goto skip;
	}

	/* decode small or large CID */
	if(!rohc_decomp_decode_cid(decomp, walk, remain_len, &stream->cid,
	                           &add_cid_len, &large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "failed to decode small or large CID in packet");
		goto error_malformed;
	}
	stream->cid_found = true;

	/* check whether the decoded CID is allowed by the decompressor */
	if(stream->cid > decomp->medium.max_cid)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected CID %zu received: MAX_CID was set to %zu",
		             stream->cid, decomp->medium.max_cid);
		goto error_no_context;
	}

	/* skip add-CID if present */
	walk += add_cid_len;
	remain_len -= add_cid_len;
	rohc_buf_pull(&remain_rohc_data, add_cid_len);

	/* find the context according to the CID found in CID,
	 * create it if needed (and possible) */
	status = rohc_decomp_find_context(decomp, walk, remain_len, stream->cid,
	                                  large_cid_len, rohc_packet.time,
	                                  &stream->profile_id, &stream->context,
	                                  &is_new_context);
	if(status == ROHC_STATUS_MALFORMED)
	{
		/* no additional feedback information to collect */
		goto error_malformed;
	}
	else if(status == ROHC_STATUS_NO_CONTEXT)
	{
		/* even if the context was not found/created, the profile ID might be available */
		goto error_no_context;
	}
	assert(status == ROHC_STATUS_OK);
	profile = stream->context->profile;
	decomp->last_context = stream->context;
	rohc_decomp_debug(stream->context, "decode packet with profile '%s' (0x%04x)",
	                  rohc_get_profile_descr(profile->id), profile->id);

	/* collect information for sending feedback to decompressor */
	stream->context_found = true;
	stream->mode = stream->context->mode;
	stream->state = stream->context->state;
	if(!is_new_context)
	{
		stream->sn_bits = profile->get_sn(stream->context);
		rohc_decomp_debug(stream->context, "%zu max)", profile->msn_max_bits);
	}

	/* detect the type of the ROHC packet */
	stream->packet_type = profile->detect_pkt_type(stream->context, walk, remain_len,
	                                               large_cid_len);
	if(stream->packet_type == ROHC_PACKET_UNKNOWN)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to detect ROHC packet type");
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error_malformed;
	}
	rohc_decomp_debug(stream->context, "decode packet as '%s'",
	                  rohc_get_packet_descr(stream->packet_type));

	/* only packets that carry static informations can be received in the
	 * No Context state, other cannot */
	if(stream->state == ROHC_DECOMP_STATE_NC &&
	   !rohc_packet_carry_static_info(stream->packet_type))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "CID %zu: packet '%s' (%d) does not carry static information, "
		             "it cannot be received in No Context state",
		             stream->cid, rohc_get_packet_descr(stream->packet_type),
		             stream->packet_type);
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error_malformed;
	}
	/* only packets carrying CRC-7 or CRC-8 can be received in the Static Context
	 * state, other cannot */
	else if(stream->state == ROHC_DECOMP_STATE_SC &&
	        !rohc_packet_carry_crc_7_or_8(stream->packet_type))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "CID %zu: packet '%s' (%d) does not carry 7- or 8-bit CRC, "
		             "it cannot be received in Static Context state",
		             stream->cid, rohc_get_packet_descr(stream->packet_type),
		             stream->packet_type);
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error_malformed;
	}
	/* all packet types are allowed in Full Context state */

	/* only IR or IR-CR packet can create a new context */
	assert(stream->packet_type == ROHC_PACKET_IR ||
	       !is_new_context);

	/* decode the packet thanks to the profile-specific routines
	 * (may change the initial assumption about the packet type) */
	status = rohc_decomp_decode_pkt(decomp, stream->context, remain_rohc_data,
	                                add_cid_len, large_cid_len, uncomp_packet,
	                                &stream->packet_type, &stream->do_change_mode);
	if(status != ROHC_STATUS_OK)
	{
		/* decompression failed, free ressources if necessary */
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to decompress packet (code = %d)", status);
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error;
	}

	/* decompression was successful, replace the existing context with the
	 * new one if necessary */
	if(is_new_context)
	{
		if(decomp->contexts[stream->cid] != NULL)
		{
			context_free(decomp->contexts[stream->cid]);
		}
		decomp->contexts[stream->cid] = stream->context;
	}

	/* get the SN of the latest packet successfully decompressed */
	stream->sn_bits = profile->get_sn(stream->context);
	rohc_decomp_debug(stream->context, "%zu max)", profile->msn_max_bits);

skip:
	return ROHC_STATUS_OK;

error:
	stream->crc_failed = !!(status == ROHC_STATUS_BAD_CRC);
	decomp->last_context = NULL;
	return status;

error_malformed:
	decomp->last_context = NULL;
	return ROHC_STATUS_MALFORMED;

error_no_context:
	decomp->last_context = NULL;
	return ROHC_STATUS_NO_CONTEXT;
}


/**
 * @brief Decode one ROHC packet
 *
 * Steps:
 *  \li A. Parse the ROHC header
 *  \li B. For IR and IR-DYN packet, check for correct compressed header (CRC)
 *  \li C. Decode extracted bits
 *  \li D. Build uncompressed headers (and check for correct decompression
 *         for UO* packets)
 *  \li E. Copy the payload (if any)
 *  \li F. Update the compression context
 *
 * Steps C and D may be repeated if packet or context repair is attempted
 * upon CRC failure.
 *
 * @param decomp               The ROHC decompressor
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param add_cid_len          The length of the optional Add-CID field
 * @param large_cid_len        The length of the optional large CID field
 * @param[out] uncomp_packet   The uncompressed packet
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] do_change_mode  Whether the profile context wants to change
 *                             its operational mode or not
 * @return                     ROHC_STATUS_OK if packet is successfully decoded,
 *                             ROHC_STATUS_MALFORMED if packet is malformed,
 *                             ROHC_STATUS_BAD_CRC if a CRC error occurs,
 *                             ROHC_STATUS_ERROR if an error occurs
 */
static rohc_status_t rohc_decomp_decode_pkt(struct rohc_decomp *const decomp,
                                            struct rohc_decomp_ctxt *const context,
                                            const struct rohc_buf rohc_packet,
                                            const size_t add_cid_len,
                                            const size_t large_cid_len,
                                            struct rohc_buf *const uncomp_packet,
                                            rohc_packet_t *const packet_type,
                                            bool *const do_change_mode)
{
	const struct rohc_decomp_profile *const profile = context->profile;
	struct rohc_decomp_crc *const extr_crc_bits = &context->volat_ctxt.crc;
	void *const extr_bits = context->volat_ctxt.extr_bits;
	void *const decoded_values = context->volat_ctxt.decoded_values;

	/* length of the parsed ROHC header and of the uncompressed headers */
	size_t rohc_hdr_len;
	size_t uncomp_hdr_len;

	/* ROHC and uncompressed payloads (they are the same) */
	const uint8_t *payload_data;
	size_t payload_len;

	/* Whether to attempt packet correction or not */
	bool try_decoding_again;

	/* helper variables for values returned by functions */
	bool parsing_ok;
	bool decode_ok;
	rohc_status_t build_ret;

	assert(add_cid_len == 0 || add_cid_len == 1);
	assert(large_cid_len <= 2);
	assert((*packet_type) != ROHC_PACKET_UNKNOWN);

	/* A. Parse the ROHC header */

	rohc_decomp_debug(context, "parse packet type '%s' (%d)",
	                  rohc_get_packet_descr(*packet_type), *packet_type);

	/* let's parse the packet! */
	parsing_ok = profile->parse_pkt(context, rohc_packet, large_cid_len,
	                                packet_type, extr_crc_bits, extr_bits,
	                                &rohc_hdr_len);
	if(!parsing_ok)
	{
		rohc_decomp_warn(context, "failed to parse the %s header",
		                 rohc_get_packet_descr(*packet_type));
		goto error_malformed;
	}

	/* ROHC base header is now fully parsed,
	 * remaining data is the payload */
	payload_data = rohc_buf_data(rohc_packet) + rohc_hdr_len;
	payload_len = rohc_packet.len - rohc_hdr_len;
	rohc_decomp_debug(context, "ROHC payload (length = %zu bytes) starts at "
	                  "offset %zu", payload_len, rohc_hdr_len);


	/*
	 * B. Check for correct compressed header (CRC)
	 *
	 * Use the CRC on compressed headers to check whether IR header was
	 * correctly received. The optional Add-CID is part of the CRC.
	 */

	if(rohc_packet_is_ir(*packet_type))
	{
		bool crc_ok;

		assert(extr_crc_bits->type == ROHC_CRC_TYPE_NONE);
		assert(extr_crc_bits->bits_nr == 8);

		crc_ok = rohc_decomp_check_ir_crc(decomp, context,
		                                  rohc_buf_data(rohc_packet) - add_cid_len,
		                                  add_cid_len + rohc_hdr_len, add_cid_len,
		                                  large_cid_len, extr_crc_bits->bits);
		if(!crc_ok)
		{
			rohc_decomp_warn(context, "CRC detected a transmission failure for "
			                 "%s packet", rohc_get_packet_descr(*packet_type));
			if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
			{
				rohc_dump_buf(decomp->trace_callback, decomp->trace_callback_priv,
				              ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING, "ROHC header",
				              rohc_buf_data(rohc_packet) - add_cid_len,
				              rohc_hdr_len + add_cid_len);
			}
#ifndef ROHC_NO_IR_CRC_CHECK
			goto error_crc;
#endif
		}

		/* reset the correction attempt */
		context->crc_corr.counter = 0;
	}


	try_decoding_again = false;
	do
	{
		if(try_decoding_again)
		{
			rohc_decomp_warn(context, "CID %zu: CRC repair: try decoding packet "
			                 "again with new assumptions", context->cid);
		}


		/* C. Decode extracted bits
		 *
		 * All bits are now extracted from the packet, let's decode them.
		 */

		decode_ok = profile->decode_bits(context, extr_bits, payload_len,
		                                 decoded_values);
		if(!decode_ok)
		{
			rohc_decomp_warn(context, "failed to decode values from bits "
			                 "extracted from ROHC header");
			goto error;
		}


		/* D. Build uncompressed headers & check for correct decompression
		 *
		 * All fields are now decoded, let's build the uncompressed headers.
		 *
		 * Use the CRC on decompressed headers to check whether decompression was
		 * correct.
		 */

		/* build the uncompressed headers */
		build_ret = profile->build_hdrs(decomp, context, *packet_type, extr_crc_bits,
		                                decoded_values, payload_len,
		                                uncomp_packet, &uncomp_hdr_len);
		if(build_ret == ROHC_STATUS_OK)
		{
			/* uncompressed headers successfully built and CRC is correct,
			 * no need to try decoding with different values */
			rohc_buf_pull(uncomp_packet, uncomp_hdr_len);

			if(context->crc_corr.algo == ROHC_DECOMP_CRC_CORR_SN_NONE)
			{
				rohc_decomp_debug(context, "CRC is correct");
			}
			else if((*packet_type) == ROHC_PACKET_IR)
			{
				rohc_decomp_debug(context, "CRC is correct, stop CRC repair");
				context->crc_corr.algo = ROHC_DECOMP_CRC_CORR_SN_NONE;
				context->crc_corr.counter = 0;
			}
			else
			{
				rohc_decomp_debug(context, "CID %zu: CRC repair: CRC is correct",
				                  context->cid);
				try_decoding_again = false;
			}
		}
		else if(build_ret == ROHC_STATUS_OUTPUT_TOO_SMALL)
		{
			rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
			                 "headers: output buffer too small", context->cid);
			goto error_output_too_small;
		}
		else if(build_ret != ROHC_STATUS_BAD_CRC)
		{
			/* uncompressed headers cannot be built, stop decoding */
			rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
			                 "headers", context->cid);
			if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
			{
				rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
				                 ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
				                 "compressed headers", rohc_packet);
			}
			goto error;
		}
		else
		{
			/* uncompressed headers successfully built but CRC is incorrect,
			 * try decoding with different values (repair) */

			/* CRC for IR and IR-DYN packets checked before, so cannot fail here */
			assert((*packet_type) != ROHC_PACKET_IR);
			assert((*packet_type) != ROHC_PACKET_IR_DYN);

			rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
			                 "headers (CRC failure)", context->cid);

			/* attempt a context/packet repair */
			try_decoding_again =
				profile->attempt_repair(decomp, context, rohc_packet.time,
				                        &context->crc_corr, extr_bits);

			/* report CRC failure if attempt is not possible */
			if(!try_decoding_again)
			{
				/* uncompressed headers successfully built, CRC is incorrect, repair
				 * was disabled or attempted without any success, so give up */
				rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
				                 "headers (CRC failure)", context->cid);
				if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
				{
					rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
					                 ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
					                 "compressed headers", rohc_packet);
				}
				goto error_crc;
			}
		}
	}
	while(try_decoding_again);

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(context->crc_corr.algo != ROHC_DECOMP_CRC_CORR_SN_NONE)
	{
		if(context->crc_corr.counter > 1)
		{
			/* update context with decoded values even if we drop the packet */
			rohc_decomp_update_context(context, decoded_values, payload_len,
			                           rohc_packet.time, do_change_mode);

			context->crc_corr.counter--;
			rohc_decomp_warn(context, "CID %zu: CRC repair: throw away packet, "
			                 "still %zu CRC-valid packets required",
			                 context->cid, context->crc_corr.counter);

			goto error_crc;
		}
		else if(context->crc_corr.counter == 1)
		{
			rohc_decomp_warn(context, "CID %zu: CRC repair: correction is "
			                 "successful, keep packet", context->cid);
			context->corrected_crc_failures++;
			decomp->stats.corrected_crc_failures++;
			switch(context->crc_corr.algo)
			{
				case ROHC_DECOMP_CRC_CORR_SN_WRAP:
					context->corrected_sn_wraparounds++;
					decomp->stats.corrected_sn_wraparounds++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_UPDATES:
					context->corrected_wrong_sn_updates++;
					decomp->stats.corrected_wrong_sn_updates++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_NONE:
				default:
					rohc_error(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					           "CID %zu: CRC repair: unsupported repair algorithm %d",
					           context->cid, context->crc_corr.algo);
					assert(0);
					goto error;
			}
			context->crc_corr.algo = ROHC_DECOMP_CRC_CORR_SN_NONE;
			context->crc_corr.counter--;
		}
	}


	/* E. Copy the payload (if any) */

	if((rohc_hdr_len + payload_len) != rohc_packet.len)
	{
		rohc_decomp_warn(context, "ROHC %s header (%zu bytes) and payload "
		                 "(%zu bytes) do not match the full ROHC packet "
		                 "(%zu bytes)", rohc_get_packet_descr(*packet_type),
		                 rohc_hdr_len, payload_len, rohc_packet.len);
		goto error;
	}
	if(rohc_buf_avail_len(*uncomp_packet) < payload_len)
	{
		rohc_decomp_warn(context, "uncompressed packet too small (%zu bytes "
		                 "max) for the %zu-byte payload",
		                 rohc_buf_avail_len(*uncomp_packet), payload_len);
		goto error_output_too_small;
	}
	if(payload_len != 0)
	{
		rohc_buf_append(uncomp_packet, payload_data, payload_len);
		rohc_buf_pull(uncomp_packet, payload_len);
	}
	/* unhide the uncompressed headers and payload */
	rohc_buf_push(uncomp_packet, uncomp_hdr_len + payload_len);
	rohc_decomp_debug(context, "uncompressed packet length = %zu bytes",
	                  uncomp_packet->len);


	/* F. Update the compression context
	 *
	 * Once CRC check is done, update the compression context with the values
	 * that were decoded earlier.
	 *
	 * TODO: check what fields shall be updated in the context
	 */

	/* we are either already in full context state or we can transit
	 * through it */
	if(context->state != ROHC_DECOMP_STATE_FC)
	{
		rohc_decomp_debug(context, "change from state %d to state %d",
		                  context->state, ROHC_DECOMP_STATE_FC);
		context->state = ROHC_DECOMP_STATE_FC;
	}

	/* update context with decoded values */
	rohc_decomp_update_context(context, decoded_values, payload_len,
	                           rohc_packet.time, do_change_mode);

	/* update statistics */
	rohc_decomp_stats_add_success(context, rohc_hdr_len, uncomp_hdr_len);

	/* decompression is successful */
	return ROHC_STATUS_OK;

error:
	return ROHC_STATUS_ERROR;
error_output_too_small:
	return ROHC_STATUS_OUTPUT_TOO_SMALL;
error_crc:
	return ROHC_STATUS_BAD_CRC;
error_malformed:
	return ROHC_STATUS_MALFORMED;
}


/**
 * @brief Check whether the CRC on IR or IR-DYN header is correct or not
 *
 * The CRC for IR/IR-DYN headers is always CRC-8. It is computed on the
 * whole compressed header (payload excluded, but any CID bits included).
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_hdr        The compressed IR or IR-DYN header
 * @param rohc_hdr_len    The length (in bytes) of the compressed header
 * @param add_cid_len     The length of the optional Add-CID field
 * @param large_cid_len   The length of the optional large CID field
 * @param crc_packet      The CRC extracted from the ROHC header
 * @return                true if the CRC is correct, false otherwise
 */
static bool rohc_decomp_check_ir_crc(const struct rohc_decomp *const decomp,
                                     const struct rohc_decomp_ctxt *const context,
                                     const uint8_t *const rohc_hdr,
                                     const size_t rohc_hdr_len,
                                     const size_t add_cid_len,
                                     const size_t large_cid_len,
                                     const uint8_t crc_packet)
{
	const uint8_t *crc_table;
	const rohc_crc_type_t crc_type = ROHC_CRC_TYPE_8;
	const uint8_t crc_zero[] = { 0x00 };
	unsigned int crc_comp; /* computed CRC */

	assert(decomp != NULL);
	assert(rohc_hdr != NULL);
	assert(rohc_hdr_len >= (add_cid_len + 2 + large_cid_len + 1));

	crc_table = decomp->crc_table_8;

	/* ROHC header before CRC field:
	 * optional Add-CID + IR type + Profile ID + optional large CID */
	crc_comp = crc_calculate(crc_type, rohc_hdr,
	                         add_cid_len + 2 + large_cid_len,
	                         CRC_INIT_8, crc_table);

	/* all profiles but the Uncompressed profile compute their CRC through the
	 * zeroed CRC field and the rest of the ROHC header */
	if(context->profile->id != ROHC_PROFILE_UNCOMPRESSED)
	{
		/* zeroed CRC field */
		crc_comp = crc_calculate(crc_type, crc_zero, 1, crc_comp, crc_table);

		/* ROHC header after CRC field */
		crc_comp = crc_calculate(crc_type,
		                         rohc_hdr + add_cid_len + 2 + large_cid_len + 1,
		                         rohc_hdr_len - add_cid_len - 2 - large_cid_len - 1,
		                         crc_comp, crc_table);
	}

	rohc_decomp_debug(context, "CRC-%d on compressed %zu-byte ROHC header = "
	                  "0x%x", crc_type, rohc_hdr_len, crc_comp);

	/* does the computed CRC match the one in packet? */
	if(crc_comp != crc_packet)
	{
		rohc_decomp_warn(context, "CRC failure (computed = 0x%02x, packet = "
		                 "0x%02x)", crc_comp, crc_packet);
		goto error;
	}

	/* computed CRC matches the one in packet */
	return true;

error:
	return false;
}


/**
 * @brief Update context with decoded values
 *
 * @param context              The decompression context
 * @param decoded              The decoded values to update in the context
 * @param payload_len          The length of the packet payload
 * @param pkt_arrival_time     The arrival time of the decoded ROHC packet
 * @param[out] do_change_mode  Whether the context wants to change its
 *                             operational mode or not
 */
static void rohc_decomp_update_context(struct rohc_decomp_ctxt *const context,
                                       const void *const decoded,
                                       const size_t payload_len,
                                       const struct rohc_ts pkt_arrival_time,
                                       bool *const do_change_mode)
{
	struct rohc_decomp_crc_corr_ctxt *const crc_corr = &context->crc_corr;

	/* call the profile-specific callback */
	context->profile->update_ctxt(context, decoded, payload_len, do_change_mode);

	/* update arrival time */
	crc_corr->arrival_times[crc_corr->arrival_times_index] = pkt_arrival_time;
	crc_corr->arrival_times_index =
		(crc_corr->arrival_times_index + 1) % ROHC_MAX_ARRIVAL_TIMES;
	crc_corr->arrival_times_nr =
		rohc_min(crc_corr->arrival_times_nr + 1, ROHC_MAX_ARRIVAL_TIMES);
}

/**
 * @brief Update statistics upon successful decompression
 *
 * @param context         The decompression context
 * @param comp_hdr_len    The length (in bytes) of the compressed header
 * @param uncomp_hdr_len  The length (in bytes) of the uncompressed header
 */
static void rohc_decomp_stats_add_success(struct rohc_decomp_ctxt *const context,
                                          const size_t comp_hdr_len,
                                          const size_t uncomp_hdr_len)
{
	context->header_last_compressed_size = comp_hdr_len;
	context->header_compressed_size += comp_hdr_len;
	context->header_last_uncompressed_size = uncomp_hdr_len;
	context->header_uncompressed_size += uncomp_hdr_len;
}


/**
 * @brief Reset all the statistics of the given ROHC decompressor
 *
 * @param decomp The ROHC decompressor
 */
static void rohc_decomp_reset_stats(struct rohc_decomp *const decomp)
{
	assert(decomp != NULL);
	decomp->stats.received = 0;
	decomp->stats.failed_crc = 0;
	decomp->stats.failed_no_context = 0;
	decomp->stats.failed_decomp = 0;
	decomp->stats.total_uncompressed_size = 0;
	decomp->stats.total_compressed_size = 0;
	decomp->stats.corrected_crc_failures = 0;
	decomp->stats.corrected_sn_wraparounds = 0;
	decomp->stats.corrected_wrong_sn_updates = 0;
}


/**
 * @brief Give a description for the given ROHC decompression context state
 *
 * Give a description for the given ROHC decompression context state.
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of decompression context states
 * used by the library. If unsure, ask on the mailing list.
 *
 * @param state  The decompression context state to get a description for
 * @return       A string that describes the given decompression context state
 *
 * @ingroup rohc_decomp
 */
const char * rohc_decomp_get_state_descr(const rohc_decomp_state_t state)
{
	switch(state)
	{
		case ROHC_DECOMP_STATE_NC:
			return "No Context";
		case ROHC_DECOMP_STATE_SC:
			return "Static Context";
		case ROHC_DECOMP_STATE_FC:
			return "Full Context";
		case ROHC_DECOMP_STATE_UNKNOWN:
		default:
			return "no description";
	}
}


/**
 * @brief Get some information about the last decompressed packet
 *
 * Get some information about the last decompressed packet.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_decomp_last_packet_info_t structure with the \e version_major
 * and \e version_minor fields set to one of the following supported
 * versions:
 *  - Major 0, minor 0
 *  - Major 0, minor 1
 *  - Major 0, minor 2
 *
 * See \ref rohc_decomp_last_packet_info_t for details about fields that
 * are supported in the above versions.
 *
 * @param decomp        The ROHC decompressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_last_packet_info_t
 */
bool rohc_decomp_get_last_packet_info(const struct rohc_decomp *const decomp,
                                      rohc_decomp_last_packet_info_t *const info)
{
	if(decomp == NULL)
	{
		goto error;
	}

	if(decomp->last_context == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "last context found in decompressor is not valid");
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "structure for last packet information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->context_mode = decomp->last_context->mode;
		info->context_state = decomp->last_context->state;
		info->profile_id = decomp->last_context->profile->id;
		info->nr_lost_packets = decomp->last_context->nr_lost_packets;
		info->nr_misordered_packets = decomp->last_context->nr_misordered_packets;
		info->is_duplicated = decomp->last_context->is_duplicated;

		/* new fields added by minor versions */
		switch(info->version_minor)
		{
			case 0:
				/* nothing to add */
				break;
			case 2:
				/* new fields in 0.2 */
				info->total_last_comp_size =
					decomp->last_context->total_last_compressed_size;
				info->header_last_comp_size =
					decomp->last_context->header_last_compressed_size;
				info->total_last_uncomp_size =
					decomp->last_context->total_last_uncompressed_size;
				info->header_last_uncomp_size =
					decomp->last_context->header_last_uncompressed_size;
				info->corrected_crc_failures =
					decomp->last_context->corrected_crc_failures;
				info->corrected_sn_wraparounds =
					decomp->last_context->corrected_sn_wraparounds;
				info->corrected_wrong_sn_updates =
					decomp->last_context->corrected_wrong_sn_updates;
				info->packet_type = decomp->last_context->packet_type;
				break;
			case 1:
				/* new fields in 0.1 */
				info->corrected_crc_failures =
					decomp->last_context->corrected_crc_failures;
				info->corrected_sn_wraparounds =
					decomp->last_context->corrected_sn_wraparounds;
				info->corrected_wrong_sn_updates =
					decomp->last_context->corrected_wrong_sn_updates;
				info->packet_type = decomp->last_context->packet_type;
				break;
			default:
				rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "unsupported minor version (%u) of the structure for "
				           "last packet information", info->version_minor);
				goto error;
		}
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for last "
		           "packet information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get some information about the given decompression context
 *
 * Get some information about the given decompression context.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_decomp_context_info_t structure with the \e version_major
 * and \e version_minor fields set to one of the following supported
 * versions:
 *  - Major 0, minor 0
 *
 * See \ref rohc_decomp_context_info_t for details about fields that
 * are supported in the above versions.
 *
 * @param decomp        The ROHC decompressor to get information from
 * @param cid           The Context ID to get information for
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_context_info_t
 */
bool rohc_decomp_get_context_info(const struct rohc_decomp *const decomp,
                                  const rohc_cid_t cid,
                                  rohc_decomp_context_info_t *const info)
{
	if(decomp == NULL)
	{
		goto error;
	}

	if(cid > decomp->medium.max_cid)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "decompressor does not handle CID %zu since MAX_CID is %zu",
		           cid, decomp->medium.max_cid);
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "structure for context information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		if(decomp->contexts[cid] == NULL)
		{
			info->packets_nr = 0;
			info->comp_bytes_nr = 0;
			info->uncomp_bytes_nr = 0;
			info->corrected_crc_failures = 0;
			info->corrected_sn_wraparounds = 0;
			info->corrected_wrong_sn_updates = 0;
		}
		else
		{
			info->packets_nr = decomp->contexts[cid]->num_recv_packets;
			info->comp_bytes_nr = decomp->contexts[cid]->total_compressed_size;
			info->uncomp_bytes_nr = decomp->contexts[cid]->total_uncompressed_size;
			info->corrected_crc_failures =
				decomp->contexts[cid]->corrected_crc_failures;
			info->corrected_sn_wraparounds =
				decomp->contexts[cid]->corrected_sn_wraparounds;
			info->corrected_wrong_sn_updates =
				decomp->contexts[cid]->corrected_wrong_sn_updates;
		}

		/* new fields added by minor versions */
		if(info->version_minor > 0)
		{
			rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "unsupported minor version (%u) of the structure for "
			           "context information", info->version_minor);
			goto error;
		}
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for context"
		           "information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get some general information about the decompressor
 *
 * Get some general information about the decompressor.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_decomp_general_info_t structure with the \e version_major and
 * \e version_minor fields set to one of the following supported versions:
 *  - Major 0, minor 0
 *
 * See the \ref rohc_decomp_general_info_t structure for details about fields
 * that are supported in the above versions.
 *
 * @param decomp        The ROHC decompressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_general_info_t
 */
bool rohc_decomp_get_general_info(const struct rohc_decomp *const decomp,
                                  rohc_decomp_general_info_t *const info)
{
	if(decomp == NULL)
	{
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "structure for general information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->contexts_nr = decomp->num_contexts_used;
		info->packets_nr = decomp->stats.received;
		info->comp_bytes_nr = decomp->stats.total_compressed_size;
		info->uncomp_bytes_nr = decomp->stats.total_uncompressed_size;

		/* new fields added by minor versions */
		switch(info->version_minor)
		{
			case 0:
				/* nothing to add */
				break;
			case 1:
				/* new fields in 0.1 */
				info->corrected_crc_failures = decomp->stats.corrected_crc_failures;
				info->corrected_sn_wraparounds =
					decomp->stats.corrected_sn_wraparounds;
				info->corrected_wrong_sn_updates =
					decomp->stats.corrected_wrong_sn_updates;
				break;
			default:
				rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "unsupported minor version (%u) of the structure for "
				           "general information", info->version_minor);
				goto error;
		}
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for "
		           "general information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get the CID type that the decompressor uses
 *
 * Get the CID type that the decompressor currently uses.
 *
 * @param decomp         The ROHC decompressor
 * @param[out] cid_type  The current CID type among \ref ROHC_SMALL_CID and
 *                       \ref ROHC_LARGE_CID
 * @return               true if the CID type was successfully retrieved,
 *                       false otherwise
 *
 * @ingroup rohc_decomp
 */
bool rohc_decomp_get_cid_type(const struct rohc_decomp *const decomp,
                              rohc_cid_type_t *const cid_type)
{
	if(decomp == NULL || cid_type == NULL)
	{
		goto error;
	}

	*cid_type = decomp->medium.cid_type;
	return true;

error:
	return false;
}


/**
 * @brief Get the maximal CID value the decompressor uses
 *
 * Get the maximal CID value the decompressor uses, ie. the \e MAX_CID
 * parameter defined in RFC 3095.
 *
 * @param decomp        The ROHC decompressor
 * @param[out] max_cid  The current maximal CID value
 * @return              true if MAX_CID was successfully retrieved,
 *                      false otherwise
 *
 * @ingroup rohc_decomp
 */
bool rohc_decomp_get_max_cid(const struct rohc_decomp *const decomp,
                             size_t *const max_cid)
{
	if(decomp == NULL || max_cid == NULL)
	{
		goto error;
	}

	*max_cid = decomp->medium.max_cid;
	return true;

error:
	return false;
}

/**
 * @brief Enable/disable features for ROHC decompressor
 *
 * Enable/disable features for ROHC decompressor. Features control whether
 * mechanisms defined as optional by RFCs are enabled or not.
 *
 * Available features are listed by \ref rohc_decomp_features_t. They may be
 * combined by XOR'ing them together.
 *
 * @warning Changing the feature set while library is used is not supported
 *
 * @param decomp    The ROHC decompressor
 * @param features  The feature set to enable/disable
 * @return          true if the feature set was successfully enabled/disabled,
 *                  false if a problem occurred
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_features_t
 */
bool rohc_decomp_set_features(struct rohc_decomp *const decomp,
                              const rohc_decomp_features_t features)
{
	const rohc_decomp_features_t all_features =
		ROHC_DECOMP_FEATURE_CRC_REPAIR |
		ROHC_DECOMP_FEATURE_DUMP_PACKETS;

	/* decompressor must be valid */
	if(decomp == NULL)
	{
		/* cannot print a trace without a valid decompressor */
		goto error;
	}

	/* reject unsupported features */
	if((features & all_features) != features)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "feature set 0x%x is not supported (supported features "
		             "set is 0x%x)", features, all_features);
		goto error;
	}

	/* record new feature set */
	decomp->features = features;

	return true;

error:
	return false;
}


/**
 * @brief Is the given decompression profile enabled for a decompressor?
 *
 * Is the given decompression profile enabled or disabled for a decompressor?
 *
 * @param decomp   The ROHC decompressor
 * @param profile  The profile to ask status for
 * @return         Possible return values:
 *                  \li true if the profile exists and is enabled,
 *                  \li false if the decompressor is not valid, the profile
 *                      does not exist, or the profile is disabled
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_profile_enabled(const struct rohc_decomp *const decomp,
                                 const rohc_profile_t profile)
{
	size_t i;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		if(rohc_decomp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC decompression profile (ID = %d)", profile);
		goto error;
	}

	/* return profile status */
	return decomp->enabled_profiles[i];

error:
	return false;
}


/**
 * @brief Enable a decompression profile for a decompressor
 *
 * Enable a decompression profiles for a decompressor.
 *
 * The ROHC decompressor does not use the decompression profiles that are not
 * enabled. Thus not enabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If the profile is already enabled, nothing is performed and success is
 * reported.
 *
 * @param decomp   The ROHC decompressor
 * @param profile  The profile to enable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c enable ROHC decompression profile
 * \code
        ...
\endcode
 *
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_enable_profile(struct rohc_decomp *const decomp,
                                const rohc_profile_t profile)
{
	size_t i;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		if(rohc_decomp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC decompression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as enabled */
	decomp->enabled_profiles[i] = true;
	rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	          "ROHC decompression profile (ID = %d) enabled", profile);

	return true;

error:
	return false;
}


/**
 * @brief Disable a decompression profile for a decompressor
 *
 * Disable a decompression profiles for a decompressor.
 *
 * The ROHC decompressor does not use the decompression profiles that were
 * disabled. Thus disabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If the profile is already disabled, nothing is performed and success is
 * reported.
 *
 * @param decomp   The ROHC decompressor
 * @param profile  The profile to disable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_disable_profile(struct rohc_decomp *const decomp,
                                 const rohc_profile_t profile)
{
	size_t i;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		if(rohc_decomp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC decompression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as disabled */
	decomp->enabled_profiles[i] = false;
	rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	          "ROHC decompression profile (ID = %d) disabled", profile);

	return true;

error:
	return false;
}


/**
 * @brief Enable several decompression profiles for a decompressor
 *
 * Enable several decompression profiles for a decompressor. The list of
 * profiles to enable shall stop with -1.
 *
 * The ROHC decompressor does not use the decompression profiles that are not
 * enabled. Thus not enabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already enabled, nothing is performed
 * and success is reported.
 *
 * @param decomp  The ROHC decompressor
 * @param ...     The sequence of decompression profiles to enable, the
 *                sequence shall be terminated by -1
 * @return        true if all of the profiles exist,
 *                false if at least one of the profiles does not exist
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c enable ROHC decompression profiles
 * \code
        ...
\endcode
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_enable_profiles(struct rohc_decomp *const decomp,
                                 ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(decomp == NULL)
	{
		goto error;
	}

	va_start(profiles, decomp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_decomp_enable_profile(decomp, profile_id);
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
 * @brief Disable several decompression profiles for a decompressor
 *
 * Disable several decompression profiles for a decompressor. The list of
 * profiles to disable shall stop with -1.
 *
 * The ROHC decompressor does not use the decompression profiles that were
 * disabled. Thus disabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already disabled, nothing is performed
 * and success is reported.
 *
 * @param decomp  The ROHC decompressor
 * @param ...     The sequence of decompression profiles to disable, the
 *                sequence shall be terminated by -1
 * @return        true if all of the profiles exist,
 *                false if at least one of the profiles does not exist
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profile
 */
bool rohc_decomp_disable_profiles(struct rohc_decomp *const decomp,
                                  ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(decomp == NULL)
	{
		goto error;
	}

	va_start(profiles, decomp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_decomp_disable_profile(decomp, profile_id);
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
 * @brief Set the callback function used to manage traces in decompressor
 *
 * Set the user-defined callback function used to manage traces in the
 * decompressor.
 *
 * The function will be called by the ROHC library every time it wants to
 * print something related to decompression, from errors to debug. User may
 * thus decide what traces are interesting (filter on \e level, source
 * \e entity, or \e profile) and what to do with them (print on console,
 * storage in file, syslog...).
 *
 * @warning The callback can not be modified after library initialization
 *
 * @param decomp     The ROHC decompressor
 * @param callback   Two possible cases:
 *                     \li The callback function used to manage traces
 *                     \li NULL to remove the previous callback
 * @param priv_ctxt  An optional private context, may be NULL
 * @return           true on success, false otherwise
 *
 * @ingroup rohc_decomp
 */
bool rohc_decomp_set_traces_cb2(struct rohc_decomp *decomp,
                                rohc_trace_callback2_t callback,
                                void *const priv_ctxt)
{
	/* check decompressor validity */
	if(decomp == NULL)
	{
		/* cannot print a trace without a valid decompressor */
		goto error;
	}

	/* refuse to set a new trace callback if decompressor is in use */
	if(decomp->stats.received > 0)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL, "unable to "
		           "modify the trace callback after initialization");
		goto error;
	}

	/* replace current trace callback by the new one */
	decomp->trace_callback = callback;
	decomp->trace_callback_priv = priv_ctxt;

	return true;

error:
	return false;
}


/*
 * Private functions
 */


/**
 * @brief Find the ROHC profile with the given profile ID.
 *
 * @param decomp      The ROHC decompressor
 * @param profile_id  The profile ID to search for
 * @return            The matching ROHC profile if found and enabled,
 *                    NULL if not found or disabled
 */
static const struct rohc_decomp_profile * find_profile(const struct rohc_decomp *const decomp,
                                                       const rohc_profile_t profile_id)
{
	size_t i;

	assert(decomp != NULL);

	/* search for the profile within the enabled profiles */
	for(i = 0;
	    i < D_NUM_PROFILES && rohc_decomp_profiles[i]->id != profile_id;
	    i++)
	{
	}

	if(i >= D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "decompression profile with ID 0x%04x not found",
		             profile_id);
		return NULL;
	}

	if(!decomp->enabled_profiles[i])
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "decompression profile with ID 0x%04x disabled",
		             profile_id);
		return NULL;
	}

	return rohc_decomp_profiles[i];
}


/**
 * @brief Decode the CID of a packet
 *
 * @param decomp              The ROHC decompressor
 * @param packet              The ROHC packet to extract CID from
 * @param len                 The size of the ROHC packet
 * @param[out] cid            The Context ID (CID) extracted from the ROHC packet
 * @param[out] add_cid_len    The length of add-CID in ROHC packet
 * @param[out] large_cid_len  The length of large CID in ROHC packet
 * @return                    true in case of success, false in case of failure
 */
static bool rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                   const uint8_t *packet,
                                   unsigned int len,
                                   rohc_cid_t *const cid,
                                   size_t *const add_cid_len,
                                   size_t *const large_cid_len)
{
	/* is feedback data is large enough to read add-CID or first byte
	   of large CID ? */
	if(len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "feedback data too short for add-CID or large CID");
		goto error;
	}

	if(decomp->medium.cid_type == ROHC_SMALL_CID)
	{
		/* small CID */
		*large_cid_len = 0;

		/* if add-CID is present, extract the CID value */
		*cid = rohc_add_cid_decode(packet, len);
		if((*cid) == UINT8_MAX)
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "no add-CID found, CID defaults to 0");
			*add_cid_len = 0;
			*cid = 0;
		}
		else
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "add-CID present (0x%x) contains CID = %zu",
			           packet[0], *cid);
			*add_cid_len = 1;
		}
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unexpected CID type (%d), should not happen",
		           decomp->medium.cid_type);
		assert(0);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse padding bits if some are present
 *
 * @param decomp       The ROHC decompressor
 * @param packet       The ROHC packet to parse
 */
static void rohc_decomp_parse_padding(const struct rohc_decomp *const decomp,
                                      struct rohc_buf *const packet)
{
	size_t padding_length = 0;

	/* remove all padded bytes */
	while(packet->len > 0 &&
	      rohc_decomp_packet_is_padding(rohc_buf_data(*packet)))
	{
		rohc_buf_pull(packet, 1);
		padding_length++;
	}
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "skip %zu byte(s) of padding", padding_length);
}


/**
 * @brief Find the context for the given ROHC packet
 *
 * If packet is an IR(-DYN) packet, parse it for the profile ID.
 * Searche for the context with the given CID.
 * Create a new context if needed.
 *
 * @param decomp                The ROHC decompressor
 * @param packet                The ROHC packet to parse
 * @param packet_len            The length (in bytes) of the ROHC packet
 * @param cid                   The CID that was parsed from ROHC packet
 * @param large_cid_len         The length (in bytes) of the Large CID that was
 *                              parsed from ROHC packet
 * @param arrival_time          The time at which the ROHC packet was received
 * @param[out] profile_id       The profile ID parsed from the ROHC packet
 * @param[out] context          The decompression context for the given ROHC packet
 * @param[out] context_created  Whether the packet has just been created or not
 * @return                      Possible return values:
 *                              \li ROHC_STATUS_OK if context was found,
 *                              \li ROHC_STATUS_NO_CONTEXT if no matching
 *                                  context was found and packet cannot create
 *                                  a new context (or failed to do so),
 *                              \li ROHC_STATUS_MALFORMED if packet is
 *                                  malformed
 */
static rohc_status_t rohc_decomp_find_context(struct rohc_decomp *const decomp,
                                              const uint8_t *const packet,
                                              const size_t packet_len,
                                              const rohc_cid_type_t cid,
                                              const size_t large_cid_len,
                                              const struct rohc_ts arrival_time,
                                              rohc_profile_t *const profile_id,
                                              struct rohc_decomp_ctxt **const context,
                                              bool *const context_created)
{
	const uint8_t *remain_data = packet;
	size_t remain_len = packet_len;
	bool new_context_needed = false;
	bool is_packet_ir_dyn;
	bool is_packet_ir_cr;
	bool is_packet_ir;

	assert(large_cid_len <= 2);

	*profile_id = ROHC_PROFILE_GENERAL;
	*context = NULL;
	*context_created = false;

	/* we need at least 1 byte for packet type */
	if(remain_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "ROHC packet too small to read the first byte that "
		             "contains the packet type (len = %zu)", remain_len);
		goto error_malformed;
	}

	/* get the profile ID from IR and IR-DYN packets */
	is_packet_ir = rohc_decomp_packet_is_ir(remain_data, remain_len);
	is_packet_ir_dyn = rohc_decomp_packet_is_irdyn(remain_data, remain_len);
	if(is_packet_ir || is_packet_ir_dyn)
	{
		const uint8_t pkt_type = remain_data[0];
		uint8_t pkt_profile_id;

		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "ROHC packet is an IR, IR-CR or IR-DYN packet");

		/* skip the type octet */
		remain_data++;
		remain_len--;

		/* skip the large CID octets if any*/
		remain_data += large_cid_len;
		remain_len -= large_cid_len;

		/* get the profile ID */
		if(remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "ROHC packet too small to read the profile ID byte "
			             "(len = %zu)", remain_len);
			goto error_malformed;
		}
		pkt_profile_id = remain_data[0];
		*profile_id = pkt_profile_id; /* TODO: ROHCv2 profiles not handled yet */
		remain_data++;
		remain_len--;
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "profile ID 0x%04x found in IR(-CR|-DYN) packet", *profile_id);

		is_packet_ir_cr = !!(pkt_profile_id == ROHC_PROFILE_TCP && (pkt_type & 0x01) == 0);
		is_packet_ir = (is_packet_ir && !is_packet_ir_cr);
	}
	else
	{
		is_packet_ir_cr = false;
	}

	/* find the context associated with the CID */
	*context = find_context(decomp, cid);
	if((*context) == NULL)
	{
		/* the decompression context did not exist yet */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "context with CID %u not found", cid);

		/* only IR packets can create new contexts */
		if(!is_packet_ir && !is_packet_ir_cr)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "only IR or IR-CR packets can create a new context with CID %u", cid);
			goto error_no_context;
		}

		/* IR or IR-CR shall create a new context */
		new_context_needed = true;
	}
	else
	{
		/* the decompression context did exist */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "context with CID %u found", cid);

		/* for IR(-CR|-DYN) packets, check whether the packet redefines the profile
		 * associated with the context */
		if((is_packet_ir || is_packet_ir_cr || is_packet_ir_dyn) &&
		   (*context)->profile->id != (*profile_id))
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "IR(-CR|-DYN) packet redefines the profile associated to the "
			           "context with CID %u: %s (0x%04x) -> %s (0x%04x)", cid,
			           rohc_get_profile_descr((*context)->profile->id),
			           (*context)->profile->id,
			           rohc_get_profile_descr(*profile_id), *profile_id);
			if(is_packet_ir || is_packet_ir_cr)
			{
				/* IR(-CR) packets: profile switching is handled by re-creating the
				 * context from scratch */
				new_context_needed = true;
			}
			else
			{
				/* IR-CR or IR-DYN packet: TODO: profile switching is not implemented
				 * yet, send a STATIC-NACK to the compressor so that it fallbacks on
				 * sending an IR packet instead of the IR-DYN packet */
				goto error_no_context;
			}
		}
	}

	/* create a new context if needed */
	if(new_context_needed)
	{
		const struct rohc_decomp_profile *profile;

		/* find the profile specified in the ROHC packet */
		profile = find_profile(decomp, *profile_id);
		if(profile == NULL)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to find profile identified by ID 0x%04x",
			             *profile_id);
			goto error_no_context;
		}

		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "create new context with CID %u and profile '%s' (0x%04x)",
		           cid, rohc_get_profile_descr(*profile_id), *profile_id);
		*context = context_create(decomp, cid, profile, arrival_time);
		if((*context) == NULL)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to create a new context with CID %u and "
			             "profile 0x%04x", cid, *profile_id);
			goto error_no_context;
		}
		*context_created = true;
	}
	else
	{
		*profile_id = (*context)->profile->id;
	}
	assert((*context)->profile != NULL);

	return ROHC_STATUS_OK;

error_malformed:
	return ROHC_STATUS_MALFORMED;
error_no_context:
	return ROHC_STATUS_NO_CONTEXT;
}

/**
 * @brief Create the array of decompression contexts
 *
 * The maximum size of the array is \ref ROHC_SMALL_CID_MAX + 1.
 *
 * @param decomp   The ROHC decompressor
 * @param max_cid  The MAX_CID value to used
 * @return         true if the contexts were created, false otherwise
 */
static bool rohc_decomp_create_contexts(struct rohc_decomp *const decomp,
                                        const rohc_cid_t max_cid)
{
	assert(decomp != NULL);
	assert(max_cid <= ROHC_SMALL_CID_MAX);

	/* allocate memory for the new context array */
	decomp->contexts = calloc(max_cid + 1, sizeof(struct rohc_decomp_ctxt *));
	if(decomp->contexts == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "cannot allocate memory for the contexts");
		return false;
	}
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "room for %zu decompression contexts created", max_cid + 1);

	return true;
}

