/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

// 把私钥数据加载到SSL上下文中
tls_wrapper_err_t openssl_tls_use_privkey(tls_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					  void *privkey_buf, size_t privkey_len)
{
	RTLS_DEBUG("ctx %p, privkey_buf %p, privkey_len %zu\n", ctx, privkey_buf, privkey_len);

	if (!ctx || !privkey_buf || !privkey_len)
		return -TLS_WRAPPER_ERR_INVALID;

	// 将tls_wrapper_ctx_t结构体中tls_private类型的指针赋值给openssl_ctx_t类型的指针
	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;

	int EPKEY;

	if (algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
		EPKEY = EVP_PKEY_EC;
	} else if (algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
		EPKEY = EVP_PKEY_RSA;
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	// 从ASN.1编码的私钥中加载私钥数据到SSL上下文（ssl_ctx->sctx）中
	int ret = SSL_CTX_use_PrivateKey_ASN1(EPKEY, ssl_ctx->sctx, privkey_buf, (long)privkey_len);

	if (ret != SSL_SUCCESS) {
		RTLS_ERR("failed to use private key %d\n", ret);
		return OPENSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
