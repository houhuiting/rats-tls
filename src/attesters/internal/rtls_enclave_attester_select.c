/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/attester.h"
#include "internal/core.h"

// 根据不同的attester实例，设置了不同的init方法。此处调用被选中实例的init方法（初始化私钥）
static rats_tls_err_t init_enclave_attester(rtls_core_context_t *ctx,
					    enclave_attester_ctx_t *attester_ctx,
					    rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("called enclave core ctx: %p enclave attester ctx: %p algo: %u\n", ctx,
		   attester_ctx, algo);

	enclave_attester_err_t err = attester_ctx->opts->init(attester_ctx, algo);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		return -RATS_TLS_ERR_INIT;

	if (!attester_ctx->attester_private)
		return -RATS_TLS_ERR_INIT;

	return RATS_TLS_ERR_NONE;
}

// 根据attester名字，选择attester实例
rats_tls_err_t rtls_attester_select(rtls_core_context_t *ctx, const char *name,
				    rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("selecting the enclave attester '%s' cert algo '%#x'...\n", name, algo);

	/* Explicitly specify the enclave attester which will never be changed */
	if (name)
		ctx->flags |= RATS_TLS_CONF_FLAGS_ATTESTER_ENFORCED;

	enclave_attester_ctx_t *attester_ctx = NULL;

	// enclave_attesters_ctx数组中存放了pre_init成功的attester实例的enclave_attesters_ctx结构体
	// 遍历一遍enclave_attesters_ctx数组，将所选择的attester实例的enclave_attester_ctx_t参数放到attester_ctx中
	for (unsigned int i = 0; i < registerd_enclave_attester_nums; ++i) {
		if (name && strcmp(name, enclave_attesters_ctx[i]->opts->name))
			continue;

		attester_ctx = malloc(sizeof(*attester_ctx));
		if (!attester_ctx)
			return -RATS_TLS_ERR_NO_MEM;

		memcpy(attester_ctx, enclave_attesters_ctx[i], sizeof(*attester_ctx));

		/* Set necessary configurations from rats_tls_init() to
		 * make init() working correctly.
		 */
		// 设置一下log如何输出
		attester_ctx->log_level = ctx->config.log_level;

		// 根据不同的attester实例，设置了不同的init方法。此处调用被选中实例的init方法（初始化私钥）
		if (init_enclave_attester(ctx, attester_ctx, algo) == RATS_TLS_ERR_NONE)
			break;

		free(attester_ctx);
		attester_ctx = NULL;
	}

	if (!attester_ctx) {
		if (!name)
			RTLS_ERR("failed to select an enclave attester\n");
		else
			RTLS_ERR("failed to select the enclave attester '%s'\n", name);

		return -RATS_TLS_ERR_INVALID;
	}

	// 将被选中attester实例的enclave_attester_ctx_t参数attester_ctx，放入核心层的rtls_core_context_t结构体参数ctx中
	ctx->attester = attester_ctx;
	ctx->flags |= RATS_TLS_CTX_FLAGS_QUOTING_INITIALIZED;

	RTLS_INFO("the enclave attester '%s' selected\n", ctx->attester->opts->name);

	return RATS_TLS_ERR_NONE;
}
