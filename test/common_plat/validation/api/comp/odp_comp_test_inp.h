/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef ODP_COMP_TEST_INP_
#define ODP_COMP_TEST_INP_

#include <odp_cunit_common.h>

/* Suite names */
#define ODP_COMP_SYNC_INP         "odp_comp_sync_inp"
#define ODP_COMP_ASYNC_INP        "odp_comp_async_inp"
#define ODP_COMP_PACKET_SYNC_INP  "odp_comp_packet_sync_inp"
#define ODP_COMP_PACKET_ASYNC_INP "odp_comp_packet_async_inp"

/* Suite test array */
extern odp_testinfo_t comp_suite[];

int comp_suite_sync_init(void);
int comp_suite_async_init(void);
int comp_suite_packet_sync_init(void);
int comp_suite_packet_async_init(void);
int comp_suite_term(void);

#endif
