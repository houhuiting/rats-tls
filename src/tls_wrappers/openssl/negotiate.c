/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/err.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

extern int verify_certificate(int preverify_ok, X509_STORE_CTX *store);

// 使用openssl去设置ssl参数和验证TLS证书的验证回调函数，并进行握手
tls_wrapper_err_t openssl_internal_negotiate(tls_wrapper_ctx_t *ctx, unsigned long conf_flags,
					     int fd, int (*verify)(int, X509_STORE_CTX *))
{
	openssl_ctx_t *ssl_ctx = ctx->tls_private;

	/*
	 * Set the verification mode.
	 * Refer to https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_verify.html
	 *
	 * client: SSL_VERIFY_PEER
	 * server: SSL_VERIFY_NONE
	 * client+mutual: SSL_VERIFY_PEER
	 * server+mutual: SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	 */
	// 根据conf_flags，设置验证mode
	if (verify) {
		int mode = SSL_VERIFY_NONE;

		if (!(conf_flags & RATS_TLS_CONF_FLAGS_SERVER))
			mode |= SSL_VERIFY_PEER;
		else if (conf_flags & RATS_TLS_CONF_FLAGS_MUTUAL)
			mode |= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

		// 设置SSL上下文（SSL_CTX）的验证TLS证书的验证回调函数
		// SSL_VERIFY_NONE: 不进行验证。
		// SSL_VERIFY_PEER: 对对方进行验证。
		// SSL_VERIFY_FAIL_IF_NO_PEER_CERT: 如果没有对方的证书，验证失败
		SSL_CTX_set_verify(ssl_ctx->sctx, mode, verify);
	}

	// 使用SSL上下文，创建一个新的SSL连接
	SSL *ssl = SSL_new(ssl_ctx->sctx);
	if (!ssl)
		return -TLS_WRAPPER_ERR_NO_MEM;

	// 用于获取SSL上下文中的证书
	X509_STORE *cert_store = SSL_CTX_get_cert_store(ssl_ctx->sctx);
<<<<<<< HEAD
	X509_STORE_set_ex_data(cert_store, openssl_ex_data_idx, ctx);
=======
	// 获取一个新的索引，该索引可以用于存储证书存储器上下文中的自定义数据
	int ex_data_idx = X509_STORE_get_ex_new_index(0, "ex_data", NULL, NULL, NULL);
	// 将自定义数据与证书关联，该函数3个输入，第一个是X509_STORE对象的指针，第二个参数是一个索引，用于标识要设置的自定义数据，第三个参数是一个指针，指向要与索引相关联的自定义数据。
	// 这里把tls_wrapper_ctx_t *ctx给关联进去
	X509_STORE_set_ex_data(cert_store, ex_data_idx, ctx);

	int *ex_data = calloc(1, sizeof(*ex_data));
	if (!ex_data) {
		RTLS_ERR("failed to calloc ex_data\n");
		return -TLS_WRAPPER_ERR_NO_MEM;
	}

	*ex_data = ex_data_idx;
	if (!per_thread_setspecific((void *)ex_data)) {
		RTLS_ERR("failed to store ex_data\n");
		return -TLS_WRAPPER_ERR_INVALID;
	}
>>>>>>> Added code comments

	/* Attach openssl to the socket */
	// 将ssl链接和socket关联起来
	int ret = SSL_set_fd(ssl, fd);
	if (ret != SSL_SUCCESS) {
		RTLS_ERR("failed to attach SSL with fd, ret is %x\n", ret);
		return -TLS_WRAPPER_ERR_INVALID;
	}

	int err;
	if (conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
	    // 如果是服务器，则得到客户端的请求，与客户端握手，去建立 SSL/TLS 连接
		err = SSL_accept(ssl);
	else
	    // 如果是客户端，则去连接服务器，与服务器握手，去建立 SSL/TLS 连接
		err = SSL_connect(ssl);

	if (err != 1) {
		if (conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
			RTLS_DEBUG("failed to negotiate %#x\n", err);
		else
			RTLS_DEBUG("failed to connect %#x\n", err);

		print_openssl_err(ssl, err);

		return OPENSSL_ERR_CODE(err);
	}

	//如果握手成功，就将ssl写入ctx->tls_private
	ssl_ctx->ssl = ssl;

	if (conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
		RTLS_DEBUG("success to negotiate\n");
	else
		RTLS_DEBUG("success to connect\n");

	return TLS_WRAPPER_ERR_NONE;
}

// TLS Wrapper的openssl实例中的negotiate方法, fd是套接字
tls_wrapper_err_t openssl_tls_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	RTLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	// 定义一个函数指针
	int (*verify)(int, X509_STORE_CTX *) = NULL;
	// 将ctx->conf_flags单独拿出来放到conf_flags中
	unsigned long conf_flags = ctx->conf_flags;

	// 如果是client或者是双向的，就给verify函数指针赋值为verify_certificate函数，该函数在un_negotiate.c中实现
	if (!(conf_flags & RATS_TLS_CONF_FLAGS_SERVER) ||
	    (conf_flags & RATS_TLS_CONF_FLAGS_MUTUAL)) {
		verify = verify_certificate;
	}

	return openssl_internal_negotiate(ctx, conf_flags, fd, verify);
}
