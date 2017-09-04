/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include "test_vectors.h"
#include "odp_comp_test_inp.h"
#include "comp.h"

struct suite_context_s {
	odp_comp_op_mode_t op_mode;
	odp_pool_t pool;
	odp_queue_t queue;
};

static struct suite_context_s suite_context;

/**
 * Check if given compression and hash algorithms are supported
 *
 * @param comp	Compression algorithm
 * @param hash	Hash algorithm
 *
 * @retval ODP_TEST_ACTIVE when both algorithms are supported
 * @retval ODP_TEST_INACTIVE when either algorithm is not supported
 */
static int check_comp_alg_support(odp_comp_alg_t comp,
			odp_comp_hash_alg_t hash)
{
	odp_comp_capability_t capability;

	if (odp_comp_capability(&capability))
		return ODP_TEST_INACTIVE;

	/* Compression algorithms */
	switch (comp) {
	case ODP_COMP_ALG_NULL:
		if (!capability.comp_algos.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_ALG_DEFLATE:
		if (!capability.comp_algos.bit.deflate)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_ALG_ZLIB:
		if (!capability.comp_algos.bit.zlib)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_ALG_LZS:
		if (!capability.comp_algos.bit.lzs)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported compression algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	/* Hash algorithms */
	switch (hash) {
	case ODP_COMP_HASH_ALG_NONE:
		break;
	case ODP_COMP_HASH_ALG_SHA1:
		if (!capability.hash_algos.bit.sha1)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_COMP_HASH_ALG_SHA256:
		if (!capability.hash_algos.bit.sha256)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported hash algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

/** 
 **/
static void ODP_UNUSED comp_decomp_alg_test(
			odp_comp_alg_t comp_alg,
			odp_comp_hash_alg_t hash_alg,
			const uint8_t *plaintext,
			unsigned int plaintext_len)
{
	odp_comp_session_t comp_session, decomp_session;
	odp_comp_capability_t capa;
	odp_comp_ses_create_err_t status;
	odp_comp_session_param_t ses_params;
	odp_comp_op_param_t op_params;
	odp_packet_t comp_inpkt, comp_outpkt;
	odp_packet_t decomp_outpkt;
	odp_comp_op_result_t comp_result, decomp_result;
	odp_packet_seg_t seg;
	odp_event_t comp_event, decomp_event;
	odp_packet_t comp_evpkt, decomp_evpkt;
	uint32_t cmp_offset = 0, outlen = 0;
	uint32_t compare_len = 0;
	uint8_t *outdata;
	int rc;

	rc = odp_comp_capability(&capa);
	CU_ASSERT(!rc);

	if (comp_alg == ODP_COMP_ALG_NULL &&
			!(capa.comp_algos.bit.null))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_DEFLATE &&
			!(capa.comp_algos.bit.deflate))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_ZLIB &&
			!(capa.comp_algos.bit.zlib))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_LZS &&
			!(capa.comp_algos.bit.lzs))
		rc = -1;

	CU_ASSERT(!rc);

	if (hash_alg == ODP_COMP_HASH_ALG_SHA1 &&
			!(capa.hash_algos.bit.sha1))
		rc = -1;
	if (hash_alg == ODP_COMP_HASH_ALG_SHA256 &&
			!(capa.hash_algos.bit.sha256))
		rc = -1;

	CU_ASSERT(!rc);

	/* Create a compression session */
	odp_comp_session_param_init(&ses_params);
	ses_params.op = ODP_COMP_OP_COMPRESS;
	ses_params.comp_algo = comp_alg;
	ses_params.hash_algo = hash_alg;
	ses_params.compl_queue = suite_context.queue;
	ses_params.mode = suite_context.op_mode;

	rc = odp_comp_session_create(&ses_params, &comp_session, &status);
	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_COMP_SES_CREATE_ERR_NONE);
	CU_ASSERT(odp_comp_session_to_u64(comp_session) !=
		odp_comp_session_to_u64(ODP_COMP_SESSION_INVALID));

	/* Create a decompression session */
	ses_params.op = ODP_COMP_OP_DECOMPRESS;
	rc = odp_comp_session_create(&ses_params, &decomp_session, &status);
	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_COMP_SES_CREATE_ERR_NONE);
	CU_ASSERT(odp_comp_session_to_u64(decomp_session) !=
		odp_comp_session_to_u64(ODP_COMP_SESSION_INVALID));
	
	/* Allocate compression input packet */
	comp_inpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(comp_inpkt != ODP_PACKET_INVALID);
	op_params.input.pkt.packet = comp_inpkt;

	/* copy test data in to pkt memory */
	rc = odp_packet_copy_from_mem(op_params.input.pkt.packet, 0,
				plaintext_len, plaintext);
	CU_ASSERT_FATAL(!rc);

	/* Allocate compression output packet */
	comp_outpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(comp_outpkt != ODP_PACKET_INVALID);
	op_params.output.pkt.packet = comp_outpkt;

	/* Allocate decompression output packet */
	decomp_outpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(decomp_outpkt != ODP_PACKET_INVALID);
	
	op_params.output.pkt.data_range.offset = 0;
	op_params.output.pkt.data_range.length = plaintext_len;
	op_params.input.pkt.data_range.offset = 0;
	op_params.input.pkt.data_range.length = plaintext_len;
	op_params.last = 1;
	op_params.session = comp_session;

	if(suite_context.op_mode == ODP_COMP_SYNC) {
		rc = odp_comp_compress(&op_params, &comp_result);
		if(rc < 0)
			goto cleanup;
		CU_ASSERT(comp_result.err == ODP_COMP_ERR_NONE);
	}
	else {
		rc = odp_comp_compress_enq(&op_params);
		if(rc < 0)
			goto cleanup;
		/* Poll completion queue for results */
		do {
			comp_event = odp_queue_deq(suite_context.queue);
		} while (comp_event == ODP_EVENT_INVALID);
		CU_ASSERT(ODP_EVENT_PACKET == odp_event_type(comp_event));
		CU_ASSERT(ODP_EVENT_PACKET_COMP == 
				odp_event_subtype(comp_event));
		
		comp_evpkt = odp_comp_packet_from_event(comp_event);
		CU_ASSERT(ODP_EVENT_PACKET == 
			odp_event_type(odp_packet_to_event(comp_evpkt)));
		CU_ASSERT(ODP_EVENT_PACKET_COMP ==
			odp_event_subtype(odp_packet_to_event(comp_evpkt)));
		rc = odp_comp_result(comp_evpkt, &comp_result);
		CU_ASSERT(!rc);
	}

	op_params.session = decomp_session;
	op_params.input.pkt.packet = comp_result.output.pkt.packet;
	op_params.input.pkt.data_range.offset = 0;
	op_params.input.pkt.data_range.length = 
			comp_result.output.pkt.data_range.length;

	op_params.output.pkt.data_range.offset = 0;
	op_params.output.pkt.data_range.length = plaintext_len;
	op_params.last = 1;
	op_params.output.pkt.packet = decomp_outpkt;

	do {
		if(suite_context.op_mode == ODP_COMP_SYNC) {
			rc = odp_comp_decomp(&op_params, &decomp_result);
			if(rc < 0)
				goto cleanup;
		}
		else {
			rc = odp_comp_decomp_enq(&op_params);
			if(rc < 0)
				goto cleanup;
			/* Poll completion queue for results */
			do {
				decomp_event = 
					odp_queue_deq(suite_context.queue);
			} while (decomp_event == 
				ODP_EVENT_INVALID);
			CU_ASSERT(ODP_EVENT_PACKET == 
					odp_event_type(decomp_event));
			CU_ASSERT(ODP_EVENT_PACKET_COMP == 
				odp_event_subtype(decomp_event));

			decomp_evpkt = 
				odp_comp_packet_from_event(decomp_event);
			CU_ASSERT(ODP_EVENT_PACKET == 
			odp_event_type(odp_packet_to_event(decomp_evpkt)));
			CU_ASSERT(ODP_EVENT_PACKET_COMP ==
			odp_event_subtype(odp_packet_to_event(decomp_evpkt)));
			rc = odp_comp_result(decomp_evpkt, &decomp_result);
			CU_ASSERT(!rc);
		}
		if(decomp_result.err == ODP_COMP_ERR_OUT_OF_SPACE) {
			rc = odp_packet_extend_tail(
				&decomp_result.output.pkt.packet,
				(plaintext_len -
				decomp_result.output.pkt.data_range.length),
				NULL, NULL);
			CU_ASSERT(!rc);
			decomp_result.output.pkt.data_range.length =
				(plaintext_len -
				decomp_result.output.pkt.data_range.length);

		}
	} while (decomp_result.err == ODP_COMP_ERR_OUT_OF_SPACE);

	seg = odp_packet_first_seg(decomp_result.output.pkt.packet);
	do {
		outdata = odp_packet_seg_data(
			decomp_result.output.pkt.packet, seg);
		outlen = odp_packet_seg_data_len(
			decomp_result.output.pkt.packet, seg);
		compare_len = outlen < (plaintext_len - cmp_offset)
			 ? outlen:(plaintext_len - cmp_offset);
		CU_ASSERT(!memcmp(outdata, 
			plaintext + cmp_offset, compare_len));

		cmp_offset += outlen;
		seg = odp_packet_next_seg(
			decomp_result.output.pkt.packet, seg);
	} while(seg != ODP_PACKET_SEG_INVALID || cmp_offset < plaintext_len);
	
cleanup:
	odp_packet_free(comp_inpkt);
	odp_packet_free(comp_outpkt);
	odp_packet_free(decomp_outpkt);

	rc = odp_comp_session_destroy(comp_session);
	CU_ASSERT(!rc);
	rc = odp_comp_session_destroy(decomp_session);
	CU_ASSERT(!rc);
}

static void comp_alg_test(odp_comp_alg_t comp_alg,
			odp_comp_hash_alg_t hash_alg,
			const uint8_t *plaintext,
			unsigned int plaintext_len)
{
	odp_comp_session_t comp_session;
	odp_comp_capability_t capa;
	odp_comp_ses_create_err_t status;
	odp_comp_session_param_t ses_params;
	odp_comp_op_param_t op_params;
	odp_packet_t comp_inpkt, comp_outpkt;
	odp_comp_op_result_t comp_result;
	odp_event_t comp_event;
	odp_packet_t comp_evpkt;
	int rc;

	rc = odp_comp_capability(&capa);
	CU_ASSERT(!rc);

	if (comp_alg == ODP_COMP_ALG_NULL &&
			!(capa.comp_algos.bit.null))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_DEFLATE &&
			!(capa.comp_algos.bit.deflate))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_ZLIB &&
			!(capa.comp_algos.bit.zlib))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_LZS &&
			!(capa.comp_algos.bit.lzs))
		rc = -1;

	CU_ASSERT(!rc);

	if (hash_alg == ODP_COMP_HASH_ALG_SHA1 &&
			!(capa.hash_algos.bit.sha1))
		rc = -1;
	if (hash_alg == ODP_COMP_HASH_ALG_SHA256 &&
			!(capa.hash_algos.bit.sha256))
		rc = -1;

	CU_ASSERT(!rc);

	/* Create a compression session */
	odp_comp_session_param_init(&ses_params);
	ses_params.op = ODP_COMP_OP_COMPRESS;
	ses_params.comp_algo = comp_alg;
	ses_params.hash_algo = hash_alg;
	ses_params.compl_queue = suite_context.queue;
	ses_params.mode = suite_context.op_mode;

	rc = odp_comp_session_create(&ses_params, &comp_session, &status);
	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_COMP_SES_CREATE_ERR_NONE);
	CU_ASSERT(odp_comp_session_to_u64(comp_session) !=
		odp_comp_session_to_u64(ODP_COMP_SESSION_INVALID));

	/* Allocate compression input packet */
	comp_inpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(comp_inpkt != ODP_PACKET_INVALID);
	op_params.input.pkt.packet = comp_inpkt;

	/* copy test data in to pkt memory */
	rc = odp_packet_copy_from_mem(op_params.input.pkt.packet, 0,
				plaintext_len, plaintext);
	CU_ASSERT_FATAL(!rc);

	/* Allocate compression output packet */
	comp_outpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(comp_outpkt != ODP_PACKET_INVALID);
	op_params.output.pkt.packet = comp_outpkt;

	op_params.output.pkt.data_range.offset = 0;
	op_params.output.pkt.data_range.length = plaintext_len;
	op_params.input.pkt.data_range.offset = 0;
	op_params.input.pkt.data_range.length = plaintext_len;
	op_params.last = 1;
	op_params.session = comp_session;

	if(suite_context.op_mode == ODP_COMP_SYNC) {
		rc = odp_comp_compress(&op_params, &comp_result);
		if(rc < 0)
			goto cleanup;
		CU_ASSERT(comp_result.err == ODP_COMP_ERR_NONE);
	}
	else {
		rc = odp_comp_compress_enq(&op_params);
		if(rc < 0)
			goto cleanup;
		/* Poll completion queue for results */
		do {
			comp_event = odp_queue_deq(suite_context.queue);
		} while (comp_event == ODP_EVENT_INVALID);
		CU_ASSERT(ODP_EVENT_PACKET == odp_event_type(comp_event));
		CU_ASSERT(ODP_EVENT_PACKET_COMP == 
				odp_event_subtype(comp_event));
		
		comp_evpkt = odp_comp_packet_from_event(comp_event);
		CU_ASSERT(ODP_EVENT_PACKET == 
			odp_event_type(odp_packet_to_event(comp_evpkt)));
		CU_ASSERT(ODP_EVENT_PACKET_COMP ==
			odp_event_subtype(odp_packet_to_event(comp_evpkt)));
		rc = odp_comp_result(comp_evpkt, &comp_result);
		CU_ASSERT(!rc);
	}

cleanup:
	odp_packet_free(comp_inpkt);
	odp_packet_free(comp_outpkt);

	rc = odp_comp_session_destroy(comp_session);
	CU_ASSERT(!rc);
}

static void decomp_alg_test(odp_comp_alg_t comp_alg,
			odp_comp_hash_alg_t hash_alg,
			const uint8_t *comptext,
			unsigned int comptext_len,
			const uint8_t *plaintext,
			unsigned int plaintext_len)
{
	odp_comp_session_t decomp_session;
	odp_comp_capability_t capa;
	odp_comp_ses_create_err_t status;
	odp_comp_session_param_t ses_params;
	odp_comp_op_param_t op_params;
	odp_packet_t decomp_inpkt, decomp_outpkt;
	odp_comp_op_result_t decomp_result;
	odp_packet_seg_t seg;
	odp_packet_t decomp_evpkt;
	odp_event_t decomp_event;
	uint32_t cmp_offset = 0, outlen = 0;
	uint32_t compare_len = 0;
	uint8_t *outdata;
	int rc;

	rc = odp_comp_capability(&capa);
	CU_ASSERT(!rc);

	if (comp_alg == ODP_COMP_ALG_NULL &&
			!(capa.comp_algos.bit.null))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_DEFLATE &&
			!(capa.comp_algos.bit.deflate))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_ZLIB &&
			!(capa.comp_algos.bit.zlib))
		rc = -1;
	if (comp_alg == ODP_COMP_ALG_LZS &&
			!(capa.comp_algos.bit.lzs))
		rc = -1;

	CU_ASSERT(!rc);

	if (hash_alg == ODP_COMP_HASH_ALG_SHA1 &&
			!(capa.hash_algos.bit.sha1))
		rc = -1;
	if (hash_alg == ODP_COMP_HASH_ALG_SHA256 &&
			!(capa.hash_algos.bit.sha256))
		rc = -1;

	CU_ASSERT(!rc);

	/* Create a decompression session */
	odp_comp_session_param_init(&ses_params);
	ses_params.op = ODP_COMP_OP_DECOMPRESS;
	ses_params.comp_algo = comp_alg;
	ses_params.hash_algo = hash_alg;
	ses_params.compl_queue = suite_context.queue;
	ses_params.mode = suite_context.op_mode;
	rc = odp_comp_session_create(&ses_params, &decomp_session, &status);
	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_COMP_SES_CREATE_ERR_NONE);
	CU_ASSERT(odp_comp_session_to_u64(decomp_session) !=
		odp_comp_session_to_u64(ODP_COMP_SESSION_INVALID));
	
	/* Allocate decompression input packet */
	decomp_inpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(decomp_inpkt != ODP_PACKET_INVALID);
	op_params.input.pkt.packet = decomp_inpkt;

	/* copy test data in to pkt memory */
	rc = odp_packet_copy_from_mem(op_params.input.pkt.packet, 0,
				comptext_len, comptext);
	CU_ASSERT_FATAL(!rc);

	/* Allocate decompression output packet */
	decomp_outpkt = odp_packet_alloc(suite_context.pool, plaintext_len);
	CU_ASSERT(decomp_outpkt != ODP_PACKET_INVALID);
	
	op_params.session = decomp_session;
	op_params.input.pkt.packet = decomp_inpkt;
	op_params.input.pkt.data_range.offset = 0;
	op_params.input.pkt.data_range.length = comptext_len;

	op_params.output.pkt.data_range.offset = 0;
	op_params.output.pkt.data_range.length = plaintext_len;
	op_params.last = 1;
	op_params.output.pkt.packet = decomp_outpkt;

	do {
		if(suite_context.op_mode == ODP_COMP_SYNC) {
			rc = odp_comp_decomp(&op_params, &decomp_result);
			if(rc < 0)
				goto cleanup;
		}
		else {
			rc = odp_comp_decomp_enq(&op_params);
			if(rc < 0)
				goto cleanup;
			/* Poll completion queue for results */
			do {
				decomp_event =
					odp_queue_deq(suite_context.queue);
			} while (decomp_event ==
				ODP_EVENT_INVALID);
			CU_ASSERT(ODP_EVENT_PACKET ==
					odp_event_type(decomp_event));
			CU_ASSERT(ODP_EVENT_PACKET_COMP ==
				odp_event_subtype(decomp_event));

			decomp_evpkt =
				odp_comp_packet_from_event(decomp_event);
			CU_ASSERT(ODP_EVENT_PACKET ==
			odp_event_type(odp_packet_to_event(decomp_evpkt)));
			CU_ASSERT(ODP_EVENT_PACKET_COMP ==
			odp_event_subtype(odp_packet_to_event(decomp_evpkt)));
			rc = odp_comp_result(decomp_evpkt, &decomp_result);
			CU_ASSERT(!rc);
		}
		if(decomp_result.err == ODP_COMP_ERR_OUT_OF_SPACE) {
			rc = odp_packet_extend_tail(
				&decomp_result.output.pkt.packet,
				(plaintext_len -
				decomp_result.output.pkt.data_range.length),
				NULL, NULL);
			CU_ASSERT(!rc);
			decomp_result.output.pkt.data_range.length =
				(plaintext_len -
				decomp_result.output.pkt.data_range.length);
		}
	} while (decomp_result.err == ODP_COMP_ERR_OUT_OF_SPACE);

	seg = odp_packet_first_seg(decomp_result.output.pkt.packet);
	do {
		outdata = odp_packet_seg_data(
			decomp_result.output.pkt.packet, seg);
		outlen = odp_packet_seg_data_len(
			decomp_result.output.pkt.packet, seg);
		compare_len = outlen < (plaintext_len - cmp_offset) ?
			outlen:(plaintext_len - cmp_offset);

		CU_ASSERT(!memcmp(outdata,
			plaintext + cmp_offset, compare_len));
		cmp_offset += outlen;
		seg = odp_packet_next_seg(
			decomp_result.output.pkt.packet, seg);
	} while(seg != ODP_PACKET_SEG_INVALID || cmp_offset < plaintext_len);
	
cleanup:
	odp_packet_free(decomp_inpkt);
	odp_packet_free(decomp_outpkt);

	rc = odp_comp_session_destroy(decomp_session);
	CU_ASSERT(!rc);
}

static int check_comp_alg_deflate(void)
{
	return check_comp_alg_support(ODP_COMP_ALG_DEFLATE,
		ODP_COMP_HASH_ALG_NONE);
}

void comp_test_alg_deflate(void)
{
	comp_alg_test(ODP_COMP_ALG_DEFLATE,
		ODP_COMP_HASH_ALG_NONE, plaintext, PLAIN_TEXT_SIZE);
}

void decomp_test_alg_deflate(void)
{
	decomp_alg_test(ODP_COMP_ALG_DEFLATE,
		ODP_COMP_HASH_ALG_NONE, compressed_text_def, COMP_DEFLATE_SIZE,
		plaintext, PLAIN_TEXT_SIZE);
}

static int check_comp_alg_zlib(void)
{
	return check_comp_alg_support(ODP_COMP_ALG_ZLIB,
		ODP_COMP_HASH_ALG_NONE);
}


void comp_test_alg_zlib(void)
{
	comp_alg_test(ODP_COMP_ALG_ZLIB,
		ODP_COMP_HASH_ALG_NONE, plaintext, PLAIN_TEXT_SIZE);
}

void decomp_test_alg_zlib(void)
{
	decomp_alg_test(ODP_COMP_ALG_ZLIB,
		ODP_COMP_HASH_ALG_NONE, compressed_text_zlib, COMP_ZLIB_SIZE,
		plaintext, PLAIN_TEXT_SIZE);
}


int comp_suite_sync_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	suite_context.op_mode = ODP_COMP_SYNC;
	return 0;
}

int comp_suite_async_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;
	suite_context.queue = odp_queue_lookup("comp-out");
	if (suite_context.queue == ODP_QUEUE_INVALID)
		return -1;

	suite_context.op_mode = ODP_COMP_ASYNC;
	return 0;
}

odp_testinfo_t comp_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(comp_test_alg_deflate,
				check_comp_alg_deflate),
	ODP_TEST_INFO_CONDITIONAL(comp_test_alg_zlib,
				check_comp_alg_zlib),
	ODP_TEST_INFO_CONDITIONAL(decomp_test_alg_deflate,
				check_comp_alg_deflate),
	ODP_TEST_INFO_CONDITIONAL(decomp_test_alg_zlib,
				check_comp_alg_zlib),
	ODP_TEST_INFO_NULL,
};

int comp_suite_term(void)
{
	int i;
	int first = 1;

	for (i = 0; comp_suite[i].pName; i++) {
		if (comp_suite[i].check_active &&
			comp_suite[i].check_active() == ODP_TEST_INACTIVE) {
			if (first) {
				first = 0;
				printf("\n\n  Inactive tests:\n");
			}
			printf("    %s\n", comp_suite[i].pName);
		}
	}
	return 0;
}
