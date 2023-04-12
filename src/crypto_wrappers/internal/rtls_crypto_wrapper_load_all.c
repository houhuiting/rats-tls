/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <string.h>
#include <stdlib.h>
#ifndef SGX
#include <dirent.h>
#endif
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"
#define PATTERN_SUFFIX ".so"
#ifdef SGX
#include <sgx_error.h>
#include "rtls_t.h"
#define DT_REG 8
#define DT_LNK 10
#endif
// clang-format on

static int crypto_wrapper_cmp(const void *a, const void *b)
{
	return (*(crypto_wrapper_ctx_t **)b)->opts->priority -
	       (*(crypto_wrapper_ctx_t **)a)->opts->priority;
}

// 加载在/usr/local/lib/rats-tls/crypto-wrappers目录下的所有Crypto Wrapper实例
rats_tls_err_t rtls_crypto_wrapper_load_all(void)
{
	RTLS_DEBUG("called\n");

	// 打开/usr/local/lib/rats-tls/crypto-wrappers目录
	uint64_t dir = rtls_opendir(CRYPTO_WRAPPERS_DIR);
	if (!dir) {
		RTLS_ERR("failed to open %s", CRYPTO_WRAPPERS_DIR);
		return -RATS_TLS_ERR_UNKNOWN;
	}

	// 记录/usr/local/lib/rats-tls/crypto-wrappers目录可加载实例数量
	unsigned int total_loaded = 0;
	rtls_dirent *ptr = NULL;
	while (rtls_readdir(dir, &ptr) != 1) {
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, "..")) {
			continue;
		}
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX))) {
			continue;
		}
#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG || ptr->d_type == DT_LNK) {
#endif
			// 通过读取到的文件名，去注册实例，对dlopen成功的实例，调用pre_init()方法，并将实例信息存储到crypto_wrapper_ctx_t结构体参数crypto_ctx中
			if (rtls_crypto_wrapper_load_single(ptr->d_name) == RATS_TLS_ERR_NONE)
				++total_loaded;
		}
	}

	rtls_closedir((uint64_t)dir);

	if (!total_loaded) {
		RTLS_ERR("unavailable crypto wrapper instance under %s\n", CRYPTO_WRAPPERS_DIR);
		return -RATS_TLS_ERR_LOAD_CRYPTO_WRAPPERS;
	}

	/* Sort all crypto_wrapper_ctx_t instances in the crypto_wrappers_ctx, and the higher priority
	 * instance should be sorted in front of the crypto_wrapper_ctx_t array.
	 */
	// 对所有pre_init()成功的crypto_wrapper实例的crypto_wrapper_ctx_t结构体，放到crypto_wrappers_ctx数组中
	// 现在通过crypto_wrapper_ctx_t结构体中的优先级字段，来对crypto_wrappers_ctx数组进行排序
	qsort(crypto_wrappers_ctx, crypto_wrappers_nums, sizeof(crypto_wrapper_ctx_t *),
	      crypto_wrapper_cmp);

	return RATS_TLS_ERR_NONE;
}
