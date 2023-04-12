/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include "openssl.h"

// crypto_wrapper的openssl实例生成私钥
crypto_wrapper_err_t openssl_gen_privkey(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					 uint8_t *privkey_buf, uint32_t *privkey_len)
{
	// 初始化变量
	openssl_ctx *octx = NULL;
	unsigned char *p = privkey_buf;
	BIGNUM *e = NULL;
	int len = 0;
	int ret;

	RTLS_DEBUG("ctx %p, algo %d, privkey_buf %p, privkey_len %p\n", ctx, algo, privkey_buf,
		   privkey_len);

	if (!ctx || !privkey_len)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	if (privkey_buf != NULL && *privkey_len == 0)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	RTLS_DEBUG("%d-byte private key buffer requested ...\n", *privkey_len);

	// 将crypto_wrapper_ctx_t结构体中crypto_private类型的指针赋值给openssl_ctx类型的指针
	octx = ctx->crypto_private;

	ret = -CRYPTO_WRAPPER_ERR_NO_MEM;

	// 如果使用ECC算法
	if (algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
		// 创建一个新的EC_KEY对象，并设置它的曲线，这里使用的是p256参数
		octx->eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (octx->eckey == NULL)
			goto err;

		ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;

		// 设置EC_KEY对象的ASN.1编码标志
		EC_KEY_set_asn1_flag(octx->eckey, OPENSSL_EC_NAMED_CURVE);

		/* Generating public-private key */
		// 生成EC（椭圆曲线）密钥对，函数返回值为1表示成功，返回值为0表示失败。OpenSSL库会随机选择一个私钥，并使用椭圆曲线算法计算相应的公钥
		if (!EC_KEY_generate_key(octx->eckey))
			goto err;

		/* check key */
		// 用于检查EC（椭圆曲线）密钥对的有效性。函数返回值为1表示密钥对有效，返回值为0表示密钥对无效。
		if (!EC_KEY_check_key(octx->eckey))
			goto err;

		/* Encode elliptic curve key Der */
		// 将一个EC_KEY对象中的私钥编码为DER格式的字节串，以便于存储和传输，并返回私钥长度
		len = i2d_ECPrivateKey(octx->eckey, NULL);
		if (len < 0)
			goto err;

		// 如果privkey_buf为空的话，就拿刚刚生成的私钥长度去设置privkey_len
		if (p == NULL) {
			*privkey_len = (uint32_t)len;
			return CRYPTO_WRAPPER_ERR_NONE;
		}

		ret = -CRYPTO_WRAPPER_ERR_ECC_KEY_LEN;

		if (*privkey_len < (uint32_t)len)
			goto err;

		// 将一个EC_KEY对象中的私钥编码为DER格式的字节串存储到privkey_buf中，以便于存储和传输，并返回私钥长度
		len = i2d_ECPrivateKey(octx->eckey, &p);
		if (len < 0)
			goto err;

		RTLS_DEBUG("ECC-256 private key (%d-byte) in DER format generated\n", len);

	  // 如果使用rsa算法
	} else if (algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
		// 创建一个新的RSA结构体的函数，用于RSA密钥对的生成和加密解密操作。它返回一个指向RSA结构体的指针，可以通过该指针访问RSA结构体的各种成员和属性，如公钥、私钥等
		octx->key = RSA_new();
		if (octx->key == NULL)
			goto err;

		// 创建一个新的BIGNUM结构体的函数，用于处理大数的运算，这里生成的e是公钥指数
		if ((e = BN_new()) == NULL)
			goto err;

		ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;
		// 将一个无符号长整型数值设置为BIGNUM结构体的函数。它将一个无符号长整型数值转换为BIGNUM类型，并将其赋值给指定的BIGNUM结构体。
		BN_set_word(e, RSA_F4);
		// 用于生成RSA密钥对的函数。该函数可以生成指定位数的RSA密钥对，并返回一个包含公钥和私钥的RSA结构体，octx->key是指向RSA结构体的指针，3072是要生成的RSA密钥位数，e参数是公钥指数，null是可选的回调函数指针
		if (!RSA_generate_key_ex(octx->key, 3072, e, NULL))
			goto err;

		// 将RSA私钥结构转换为DER编码格式的函数，以便于存储和传输，并返回私钥长度
		len = i2d_RSAPrivateKey(octx->key, NULL);
		if (len < 0)
			goto err;

		// 如果privkey_buf为空的话，就拿刚刚生成的私钥长度去设置privkey_len
		if (p == NULL) {
			*privkey_len = (uint32_t)len;
			return CRYPTO_WRAPPER_ERR_NONE;
		}

		ret = -CRYPTO_WRAPPER_ERR_RSA_KEY_LEN;

		if (*privkey_len < (uint32_t)len)
			goto err;

		// 将RSA私钥结构转换为DER编码格式的字节串存储到privkey_buf中，以便于存储和传输，并返回私钥长度
		len = i2d_RSAPrivateKey(octx->key, &p);
		if (len < 0)
			goto err;

		RTLS_DEBUG("RSA-3072 private key (%d-byte) in DER format generated\n", len);
	  // 只支持ecc和rsa算法
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	// 将私钥长度赋值给privkey_len
	*privkey_len = (uint32_t)len;

	return CRYPTO_WRAPPER_ERR_NONE;

// 错误处理
err:
	if (algo == RATS_TLS_CERT_ALGO_ECC_256_SHA256) {
		RTLS_DEBUG("failed to generate ECC-256 private key %d\n", ret);

		if (octx->eckey) {
			EC_KEY_free(octx->eckey);
			octx->eckey = NULL;
		}
	} else if (algo == RATS_TLS_CERT_ALGO_RSA_3072_SHA256) {
		RTLS_DEBUG("failed to generate RSA-3072 private key %d\n", ret);

		if (octx->key) {
			RSA_free(octx->key);
			octx->key = NULL;
		}

		if (e)
			BN_free(e);
	}
	return ret;
}
