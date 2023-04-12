/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

// TLS Wrapper实例的transmit方法，该方法可以用来发送数据
tls_wrapper_err_t openssl_tls_transmit(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	RTLS_DEBUG("ctx %p, buf %p, buf_size %p\n", ctx, buf, buf_size);

	if (!ctx || !buf || !buf_size)
		return -TLS_WRAPPER_ERR_INVALID;

	// 设置ssl上下文
	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;
	if (ssl_ctx == NULL || ssl_ctx->ssl == NULL)
		return -TLS_WRAPPER_ERR_TRANSMIT;

	// 将明文数据加密后发送给接收方
	int rc = SSL_write(ssl_ctx->ssl, buf, (int)*buf_size);
	if (rc <= 0) {
		RTLS_DEBUG("ERROR: tls_wrapper_openssl transmit()\n");
		return -TLS_WRAPPER_ERR_TRANSMIT;
	}
	*buf_size = (size_t)rc;

	return TLS_WRAPPER_ERR_NONE;
}
