/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_tls_use_privkey(tls_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					  uint8_t *private_key, size_t private_key_size)
{
	RTLS_DEBUG("ctx %p, private_key %p, privkey_len %zu\n", ctx, private_key, private_key_size);

	if (!ctx || !private_key || !private_key_size)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;

    /* Convert privkey in PEM format to EVP_PKEY structure */

	EVP_PKEY *pkey = NULL;
	BIO *bio = NULL;

	pkey = EVP_PKEY_new();
	if (!pkey) {
		RTLS_ERR("failed to init EVP_PKEY");
		return TLS_WRAPPER_ERR_NO_MEM;
	}
	
	bio = BIO_new_mem_buf(private_key, private_key_size);
	if (!bio) {
		RTLS_ERR("failed to init BIO");
		return TLS_WRAPPER_ERR_NO_MEM;
	}
	
	if (!PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)) {
		RTLS_ERR("failed to init BIO");
		return TLS_WRAPPER_ERR_PRIV_KEY;
	}
	BIO_free(bio);
	bio = NULL;

	int ret = SSL_CTX_use_PrivateKey(ssl_ctx->sctx, pkey);

	if (ret != SSL_SUCCESS) {
		RTLS_ERR("failed to use private key %d\n", ret);
		return OPENSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
