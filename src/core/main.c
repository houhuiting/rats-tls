/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/err.h>
#include "internal/core.h"
#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/crypto_wrapper.h"
#ifdef SGX
#include "rtls_t.h"
#endif
#include <openssl/opensslv.h>
// clang-format on

/* The global configurations present by /opt/rats-tls/config.toml */
// 一个全局的rtls_core_context_t参数global_core_context
rtls_core_context_t global_core_context;
/* The global log level used by log.h */
// 全局参数global_log_level，用于表示使用什么模式输出log
rats_tls_log_level_t global_log_level = RATS_TLS_LOG_LEVEL_DEFAULT;

#ifdef SGX
// clang-format off
#define INSTANCE_NUM  8
#define INSTANCE_NAME 32
// clang-format on
char enclave_instance_name[INSTANCE_NUM][INSTANCE_NAME] = { "nullcrypto",    "nullattester",
							    "nullverifier",  "sgx_ecdsa",
							    "sgx_ecdsa_qve", "sgx_la",
							    "nulltls",	     "openssl" };
void librats_tls_init(void)
#else
void __attribute__((constructor)) librats_tls_init(void)
#endif
{
	RTLS_DEBUG("called\n");

	global_log_level = rtls_loglevel_getenv("RATS_TLS_GLOBAL_LOG_LEVEL");
	if (global_log_level == (rats_tls_log_level_t)-1) {
		RTLS_FATAL("failed to get log level from env\n");
		rtls_exit();
	}

	/* Initialize global configurations. It is intend to leave tls_type,
	 * attester_type, verifier_type and crypto_type empty to take the
	 * best guess.
	 */
	// clang-format off
	global_core_context.config.api_version = RATS_TLS_API_VERSION_DEFAULT;
	// clang-format on
	global_core_context.config.log_level = global_log_level;
	/* FIXME: it is intended to use the certificate with different algorithm */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	global_core_context.config.cert_algo = RATS_TLS_CERT_ALGO_RSA_3072_SHA256;
#else
	global_core_context.config.cert_algo = RATS_TLS_CERT_ALGO_ECC_256_SHA256;
#endif

	/* TODO: load and parse the global configuration file */

#ifdef SGX
    // 如果是sgx模式，就要加载librats_tls.a
	for (uint8_t i = 0; i < INSTANCE_NUM; i++) {
		rats_tls_err_t err = rtls_instance_init(enclave_instance_name[i], NULL, NULL);
		if (err != RATS_TLS_ERR_NONE) {
			RTLS_ERR("failed to initialize rtls instance: %s\n",
				 enclave_instance_name[i]);
			rtls_exit();
		}
	}
#else
	/* Load all crypto wrapper instances */
	// 加载在/usr/local/lib/rats-tls/crypto-wrappers目录下的所有Crypto Wrapper实例
	rats_tls_err_t err = rtls_crypto_wrapper_load_all();
	if (err != RATS_TLS_ERR_NONE) {
		RTLS_FATAL("failed to load any crypto wrapper %#x\n", err);
		rtls_exit();
	}

	/* Load all enclave attester instances */
	// 加载在/usr/local/lib/rats-tls/attester目录下的所有Enclave Attester 实例
	err = rtls_enclave_attester_load_all();
	if (err != RATS_TLS_ERR_NONE) {
		RTLS_FATAL("failed to load any enclave attester %#x\n", err);
		rtls_exit();
	}
	/* Load all enclave verifier instances */
	// 加载在/usr/local/lib/rats-tls/verifier目录下的所有Enclave Verifier 实例
	err = rtls_enclave_verifier_load_all();
	if (err != RATS_TLS_ERR_NONE) {
		RTLS_FATAL("failed to load any enclave verifier %#x\n", err);
		rtls_exit();
	}

	/* Load all tls wrapper instances */
	// 加载在/usr/local/lib/rats-tls/tls-wrapper目录下的所有TLS Wrapper实例
	err = rtls_tls_wrapper_load_all();
	if (err != RATS_TLS_ERR_NONE) {
		RTLS_FATAL("failed to load any tls wrapper %#x\n", err);
		rtls_exit();
	}
#endif
}
