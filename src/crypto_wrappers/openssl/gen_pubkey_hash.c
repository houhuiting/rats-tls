/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include "openssl.h"

// crypto_wrapper的openssl实例生成公钥哈希值
crypto_wrapper_err_t openssl_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					     uint8_t *hash)
{
	// 初始化变量
	openssl_ctx *octx = NULL;

	RTLS_DEBUG("ctx %p, algo %d, hash %p\n", ctx, algo, hash);

	if (!ctx || !hash)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	// 将crypto_wrapper_ctx_t结构体中crypto_private类型的指针赋值给openssl_ctx类型的指针
	octx = ctx->crypto_private;

	/* Calculate hash of SubjectPublicKeyInfo object */
	// 如果使用ECC算法
	if (algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
		// 由于之前在gen_privkey函数中已经生成好了公私钥对，这里直接将EC公钥结构体转换为DER格式的字节串，并返回长度
		int len = i2d_EC_PUBKEY(octx->eckey, NULL);
		// 利用返回的公钥长度，初始化一个buffer用来存储公钥
		unsigned char buffer[len];
		unsigned char *p = buffer;

		// 将EC公钥结构体转换为DER格式的字节串，并存入buffer，返回公钥长度
		len = i2d_EC_PUBKEY(octx->eckey, &p);

		// 使用sha256的哈希方法计算hash值，并将结果放入hash
		SHA256(buffer, len, hash);

		RTLS_DEBUG(
			"the sha256 of public key [%d] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
			len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
			hash[28], hash[29], hash[30], hash[31]);
    
	  // 如果使用rsa算法
	} else if (algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
		// 由于之前在gen_privkey函数中已经生成好了公私钥对，这里直接将RSA公钥结构体转换为DER格式的字节串，并返回长度
		int len = i2d_RSA_PUBKEY(octx->key, NULL);
		// 利用返回的公钥长度，初始化一个buffer用来存储公钥
		unsigned char buffer[len];
		unsigned char *p = buffer;

		// 将RSA公钥结构体转换为DER格式的字节串存入buffer，并返回公钥长度
		len = i2d_RSA_PUBKEY(octx->key, &p);

		// 使用sha256的哈希方法计算hash值，并将结果放入hash
		SHA256(buffer, len, hash);

		RTLS_DEBUG(
			"the sha256 of public key [%d] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
			len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
			hash[28], hash[29], hash[30], hash[31]);
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	return CRYPTO_WRAPPER_ERR_NONE;
}
