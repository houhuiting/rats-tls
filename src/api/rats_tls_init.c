/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/api.h>
#include <rats-tls/log.h>
#include <rats-tls/claim.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"
#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include <openssl/opensslv.h>

// 提供给用户的init api接口
// 用于初始化和选择各种实例
rats_tls_err_t rats_tls_init(const rats_tls_conf_t *conf, rats_tls_handle *handle)
{
	if (!conf || !handle)
		return -RATS_TLS_ERR_INVALID;

	RTLS_DEBUG("conf %p, handle %p\n", conf, handle);

	// 初始化一个rtls_core_context_t参数ctx，此参数作为本函数内的临时变量，在函数结束时，将值传递到handle中，以便用户使用
	rtls_core_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -RATS_TLS_ERR_NO_MEM;

	// 将用户配置conf存放到ctx中
	ctx->config = *conf;

	rats_tls_err_t err = -RATS_TLS_ERR_INVALID;

	// 如果用户配置中的api_version非法，就进入错误处理
	if (ctx->config.api_version > RATS_TLS_API_VERSION_MAX) {
		RTLS_ERR("unsupported rats-tls api version %d > %d\n", ctx->config.api_version,
			 RATS_TLS_API_VERSION_MAX);
		goto err_ctx;
	}

	// 如果如果用户配置中的log_level非法，就使用全局参数global_core_context中的默认的log_level
	if (ctx->config.log_level < 0 || ctx->config.log_level >= RATS_TLS_LOG_LEVEL_MAX) {
		ctx->config.log_level = global_core_context.config.log_level;
		RTLS_WARN("log level reset to global value %d\n",
			  global_core_context.config.log_level);
	}

	/* FIXME: it is intended to use the certificate with different algorithm */
	// 旨在使用具有不同算法的证书
	if (ctx->config.cert_algo == RATS_TLS_CERT_ALGO_DEFAULT) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		ctx->config.cert_algo = RATS_TLS_CERT_ALGO_RSA_3072_SHA256;
#else
		ctx->config.cert_algo = RATS_TLS_CERT_ALGO_ECC_256_SHA256;
#endif
	}

	// 如果如果用户配置中的cert_algo非法，就使用全局参数global_core_context中的默认的lcert_algo
	if (ctx->config.cert_algo < 0 || ctx->config.cert_algo >= RATS_TLS_CERT_ALGO_MAX) {
		ctx->config.cert_algo = global_core_context.config.cert_algo;
		RTLS_WARN("certificate algorithm reset to global value %d\n",
			  global_core_context.config.cert_algo);
	}

	// 全局参数global_log_level，用于表示使用什么模式输出log
	global_log_level = ctx->config.log_level;

	/* Make a copy of user-defined custom claims */
	// 对用户定义的claim做一个拷贝，将conf指向的claim，复制到ctx->config指向的claim
	if (conf->custom_claims && conf->custom_claims_length) {
		RTLS_DEBUG("conf->custom_claims: %p conf->custom_claims_length: %zu\n",
			   conf->custom_claims, conf->custom_claims_length);
		ctx->config.custom_claims =
			clone_claims_list(conf->custom_claims, conf->custom_claims_length);
		err = RATS_TLS_ERR_NO_MEM;
		if (!ctx->config.custom_claims) {
			RTLS_ERR("failed to make copy of custom claims: out of memory\n");
			goto err_ctx;
		}
		ctx->config.custom_claims_length = conf->custom_claims_length;
	} else {
		ctx->config.custom_claims = NULL;
		ctx->config.custom_claims_length = 0;
	}

	/* Select the target crypto wrapper to be used */
	// 选择要使用crypto_wrapper
	// 将要选择的crypto_wrapper名字存入choice
	char *choice = ctx->config.crypto_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.crypto_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	// 根据crypto_wrapper名字，选择crypto_wrapper实例，将被选中crypto_wrapper实例的crypto_wrapper_ctx_t参数crypto_ctx，放入核心层的rtls_core_context_t结构体参数ctx中
	err = rtls_crypto_wrapper_select(ctx, choice);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target attester to be used */
	// 选择要使用attester
	// 将要选择的attester名字存入choice
	choice = ctx->config.attester_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.attester_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	// 根据attester名字，选择attester实例，将被选中attester实例的enclave_attesters_ctx参数attester_ctx，放入核心层的rtls_core_context_t结构体参数ctx中
	err = rtls_attester_select(ctx, choice, ctx->config.cert_algo);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target verifier to be used */
	// 选择要使用verifier
	// 将要选择的verifier名字存入choice
	choice = ctx->config.verifier_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.verifier_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	// 根据verifier名字，选择verifier实例，将被选中verifier实例的enclave_verifier_ctx_t参数verifier_ctx，放入核心层的rtls_core_context_t结构体参数ctx中
	err = rtls_verifier_select(ctx, choice, ctx->config.cert_algo);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target tls wrapper to be used */
	// 选择要使用tls_wrapper
	// 将要选择的tls_wrapper名字存入choice
	choice = ctx->config.tls_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.tls_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	// 根据tls_wrapper名字，选择tls_wrapper实例，将被选中tls_wrapper实例的enclave_verifier_ctx_t参数verifier_ctx，放入核心层的rtls_core_context_t结构体参数ctx中
	err = rtls_tls_wrapper_select(ctx, choice);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Check whether requiring to generate TLS certificate */
	// 生成证书
	if ((ctx->config.flags & RATS_TLS_CONF_FLAGS_SERVER) ||
	    (ctx->config.flags & RATS_TLS_CONF_FLAGS_MUTUAL)) {
		err = rtls_core_generate_certificate(ctx);
		if (err != RATS_TLS_ERR_NONE)
			goto err_ctx;
	}

	*handle = ctx;

	RTLS_DEBUG("the handle %p returned\n", ctx);

	return RATS_TLS_ERR_NONE;

err_ctx:
	free(ctx);
	return err;
}
