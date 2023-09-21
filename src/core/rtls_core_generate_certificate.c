/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/err.h>
#include "internal/core.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/dice.h"
#include <string.h>
#include <librats/api.h>

rats_tls_err_t rtls_core_generate_certificate(rtls_core_context_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts)
		return -RATS_TLS_ERR_INVALID;

	/* Avoid re-generation of TLS certificates */
	if (ctx->flags & RATS_TLS_CTX_FLAGS_CERT_CREATED)
		return RATS_TLS_ERR_NONE;

	rats_cert_subject_t subject_name = {
		.organization = (const unsigned char *)"Inclavare Containers",
		.common_name = (const unsigned char *)"RATS-TLS",
	};
	uint8_t *certificate = NULL;
	size_t certificate_size = 0;
	uint8_t *private_key = NULL;
	size_t private_key_size = 0;
	rats_conf_t conf;

	memset(&conf, 0, sizeof(rats_conf_t));

	memcpy(conf.attester_type, ctx->config.attester_type, sizeof(ctx->config.attester_type));
	memcpy(conf.crypto_type, ctx->config.crypto_type, sizeof(ctx->config.crypto_type));
	if (ctx->config.log_level == RATS_TLS_LOG_LEVEL_DEBUG) {
		conf.log_level = RATS_LOG_LEVEL_DEBUG;
	}
	else if (ctx->config.log_level == RATS_TLS_LOG_LEVEL_INFO) {
		conf.log_level = RATS_LOG_LEVEL_INFO;
	}
	else if (ctx->config.log_level == RATS_TLS_LOG_LEVEL_WARN) {
		conf.log_level = RATS_LOG_LEVEL_WARN;
	}
	else if (ctx->config.log_level == RATS_TLS_LOG_LEVEL_ERROR) {
		conf.log_level = RATS_LOG_LEVEL_ERROR;
	}
	else if (ctx->config.log_level == RATS_TLS_LOG_LEVEL_FATAL) {
		conf.log_level = RATS_LOG_LEVEL_FATAL;
	}
	else if (ctx->config.log_level == RATS_TLS_LOG_LEVEL_NONE) {
		conf.log_level = RATS_LOG_LEVEL_NONE;
	}
	else if (ctx->config.log_level == RATS_TLS_LOG_LEVEL_MAX) {
		conf.log_level = RATS_LOG_LEVEL_MAX;
	}

	librats_get_attestation_certificate(conf, subject_name, &private_key, &private_key_size, ctx->config.custom_claims, ctx->config.custom_claims_length, true, &certificate, &certificate_size);
	
	printf("The certificate length is %ld\n", certificate_size);
	for (int i = 0; i < certificate_size ;i++)
	{
		printf("%0x", certificate[i]);
	}
	printf("\n");

	/* Use the TLS certificate and private key for TLS session */
	if (private_key_size) {
		tls_wrapper_err_t t_err;

		t_err = ctx->tls_wrapper->opts->use_privkey(ctx->tls_wrapper, ctx->config.cert_algo,
							    private_key, private_key_size);
		if (t_err != TLS_WRAPPER_ERR_NONE) {
			if (certificate)
				free((void*) certificate);
			return t_err;
		}

		t_err = ctx->tls_wrapper->opts->use_cert(ctx->tls_wrapper, certificate, certificate_size);
		if (t_err != TLS_WRAPPER_ERR_NONE) {
			if (certificate)
				free((void*) certificate);
			return t_err;
		}
	}
	if (certificate)
		free(certificate);

	/* Prevent from re-generation of TLS certificate */
	ctx->flags |= RATS_TLS_CTX_FLAGS_CERT_CREATED;

	return RATS_TLS_ERR_NONE;
}
