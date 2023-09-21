/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stdio.h>
#include "rtls_t.h"

#define POSSIBLE_UNUSED __attribute__((unused))

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
	size_t ret;
	sgx_status_t POSSIBLE_UNUSED sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);

	return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
	size_t ret;
	sgx_status_t POSSIBLE_UNUSED sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);

	return ret;
}

