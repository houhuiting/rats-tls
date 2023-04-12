/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/crypto_wrapper.h"


// 注册crypto_wrapper实例
crypto_wrapper_err_t crypto_wrapper_register(const crypto_wrapper_opts_t *opts)
{
	if (!opts)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	RTLS_DEBUG("registering the crypto wrapper '%s' ...\n", opts->name);

	//将crypto_wrapper_opts_t类型的opts拷贝成一个新的参数new_opts
	crypto_wrapper_opts_t *new_opts = (crypto_wrapper_opts_t *)malloc(sizeof(*new_opts));
	if (!new_opts)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));

	//如果new_opts参数里面name字段为空，报错
	if (new_opts->name[0] == '\0') {
		RTLS_ERR("invalid crypto wrapper name\n");
		goto err;
	}

	//如果new_opts参数里面version字段大于我们所支持的版本，报错
	if (new_opts->api_version > CRYPTO_WRAPPER_API_VERSION_MAX) {
		RTLS_ERR("unsupported crypto wrapper api version %d > %d\n", new_opts->api_version,
			 CRYPTO_WRAPPER_API_VERSION_MAX);
		goto err;
	}

	// 通过上面的判断，可以得到一个合法的new_opts参数
	// 将这个new_opts参数视为一个可注册的crypto_wrapper实例的上下文信息
	// 将此上下文信息存入到crypto_wrappers_opts数组中
	// 其中，registerd_crypto_wrapper_nums是可注册的crypto_wrapper实例的数量
	crypto_wrappers_opts[registerd_crypto_wrapper_nums++] = new_opts;

	RTLS_INFO("the crypto wrapper '%s' registered\n", opts->name);

	return CRYPTO_WRAPPER_ERR_NONE;

err:
	free(new_opts);
	return -CRYPTO_WRAPPER_ERR_INVALID;
}
