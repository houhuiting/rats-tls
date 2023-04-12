/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

// clang-format off
#define PATTERN_PREFIX "libcrypto_wrapper_"
#ifdef SGX
#define PATTERN_SUFFIX ".a"
#else
#define PATTERN_SUFFIX ".so"
#endif
// clang-format on

// 调用每一个实例的pre_init()方法，对pre_init()对实例，将其信息存储到crypto_wrapper_ctx_t结构体参数crypto_ctx中
rats_tls_err_t rtls_enclave_crypto_post_init(const char *name, void *handle)
{
	unsigned int i = 0;
	crypto_wrapper_opts_t *opts = NULL;
	// 可注册的实例（dlopen成功）会讲其上下文信息存入到crypto_wrappers_opts数组中
	// 去注可注册的实例（dlopen成功）数组信息里，找到我们需要的实例
	for (i = 0; i < registerd_crypto_wrapper_nums; ++i) {
		opts = crypto_wrappers_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_crypto_wrapper_nums) {
		RTLS_DEBUG("the crypto wrapper '%s' failed to register\n", name);
		return -RATS_TLS_ERR_NOT_REGISTERED;
	}

	// 对dlopen成功的实例，执行pre_init函数，该函数由每个实例自行实现
	if (opts->pre_init) {
		crypto_wrapper_err_t err_cw = opts->pre_init();
		if (err_cw != CRYPTO_WRAPPER_ERR_NONE) {
			RTLS_ERR("failed on pre_init() of crypto wrapper '%s' %#x\n", name, err_cw);
			return -RATS_TLS_ERR_INVALID;
		}
	}

	// 将pre_init成功的实例信息，写到crypto_wrapper_ctx_t结构体参数crypto_ctx中
	crypto_wrapper_ctx_t *crypto_ctx = calloc(1, sizeof(*crypto_ctx));
	if (!crypto_ctx)
		return -RATS_TLS_ERR_NO_MEM;

	crypto_ctx->opts = opts;
	crypto_ctx->conf_flags = global_core_context.config.flags;
	crypto_ctx->log_level = global_core_context.config.log_level;
	crypto_ctx->cert_algo = global_core_context.config.cert_algo;
	crypto_ctx->handle = handle;

	// 将所有pre_init成功的crypto_wrapper实例的crypto_wrapper_ctx_t结构体，放到crypto_wrappers_ctx数组中
	crypto_wrappers_ctx[crypto_wrappers_nums++] = crypto_ctx;

	return RATS_TLS_ERR_NONE;
}

// 通过读取到的文件名，去注册实例，对dlopen成功的实例，调用pre_init()方法，并将实例信息存储到crypto_wrapper_ctx_t结构体参数crypto_ctx中
rats_tls_err_t rtls_crypto_wrapper_load_single(const char *fname)
{
	RTLS_DEBUG("loading the crypto wrapper instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up libcrypto_wrapper_<name>.so */
	// 检查文件名模式是否匹配 libcrypto_wrapper_<name>.so
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		RTLS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return -RATS_TLS_ERR_INVALID;
	}

	char realpath[strlen(CRYPTO_WRAPPERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", CRYPTO_WRAPPERS_DIR, fname);

	uint32_t name_len = (uint32_t)strlen(fname) - (uint32_t)strlen(PATTERN_PREFIX) -
			    (uint32_t)strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = NULL;
	// 调用初始化函数，从而去注册一个实例，判断实例是否能注册（dlopen成功）
	rats_tls_err_t err = rtls_instance_init(name, realpath, &handle);
	if (err != RATS_TLS_ERR_NONE)
		return err;

	// 调用每一个实例的pre_init()方法，对pre_init()对实例，将其信息存储到crypto_wrapper_ctx_t结构体参数crypto_ctx中
	err = rtls_enclave_crypto_post_init(name, handle);
	if (err != RATS_TLS_ERR_NONE)
		return err;

	RTLS_DEBUG("the crypto wrapper '%s' loaded\n", name);

	return RATS_TLS_ERR_NONE;
}
