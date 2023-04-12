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


// 生成证书
rats_tls_err_t rtls_core_generate_certificate(rtls_core_context_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts || !ctx->crypto_wrapper ||
	    !ctx->crypto_wrapper->opts || !ctx->crypto_wrapper->opts->gen_pubkey_hash ||
	    !ctx->crypto_wrapper->opts->gen_cert)
		return -RATS_TLS_ERR_INVALID;

	/* Avoid re-generation of TLS certificates */
	// 检查是否生成过证书，避免重新生成
	if (ctx->flags & RATS_TLS_CTX_FLAGS_CERT_CREATED)
		return RATS_TLS_ERR_NONE;

	/* Check whether the specified algorithm is supported.
	 *
	 * TODO: the supported algorithm list should be provided by a crypto
	 * wrapper instance, and the core logic can search a proper crypto
	 * wrapper instance to address the requesting algorithm.
	 */
	// 检查是否支持指定的加密算法
	unsigned int hash_size;

	switch (ctx->config.cert_algo) {
	case RATS_TLS_CERT_ALGO_RSA_3072_SHA256:
	case RATS_TLS_CERT_ALGO_ECC_256_SHA256:
		hash_size = SHA256_HASH_SIZE;
		break;
	default:
		RTLS_DEBUG("unknown algorithm %d\n", ctx->config.cert_algo);
		return -RATS_TLS_ERR_UNSUPPORTED_CERT_ALGO;
	}

	/* Generate the new key */
	// 调用crypto_wrapper实例生成私钥
	crypto_wrapper_err_t c_err;
	uint8_t privkey_buf[2048];
	unsigned int privkey_len = sizeof(privkey_buf);
	c_err = ctx->crypto_wrapper->opts->gen_privkey(ctx->crypto_wrapper, ctx->config.cert_algo,
						       privkey_buf, &privkey_len);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Generate the hash of public key */
	// 生成公钥哈希值
	uint8_t hash[hash_size];
	c_err = ctx->crypto_wrapper->opts->gen_pubkey_hash(ctx->crypto_wrapper,
							   ctx->config.cert_algo, hash);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Collect evidence */
	// 初始化evidence的结构体
	attestation_evidence_t evidence;
	memset(&evidence, 0, sizeof(attestation_evidence_t));

	// TODO: implement per-session freshness and put "nonce" in custom claims list.
	// 初始化claims
	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;

	/* Using sha256 hash of claims_buffer as user data */
	RTLS_DEBUG("fill evidence user-data field with sha256 of claims_buffer\n");
	/* Generate claims_buffer */
	// 调用核心层代码，生成cbor格式的claims_buffer，包括[ key: “pubkey-hash”, value: pubkey-hash-value ]和其他用户自定义的claims值
	enclave_attester_err_t a_ret = dice_generate_claims_buffer(
		HASH_ALGO_SHA256, hash, ctx->config.custom_claims, ctx->config.custom_claims_length,
		&claims_buffer, &claims_buffer_size);
	if (a_ret != ENCLAVE_ATTESTER_ERR_NONE) {
		RTLS_DEBUG("generate claims_buffer failed. a_ret: %#x\n", a_ret);
		return a_ret;
	}

	/* Note here we reuse `uint8_t hash[hash_size]` to store sha256 hash of claims_buffer */
	// 生成claims_buffer的哈希值，将结果放到hash中
	// 这里重用了hash参数，之前的hash是公钥的hash值，用于生成cbor格式的claims_buffer；现在的hash是claims_buffer的hash，将存入evidence中
	ctx->crypto_wrapper->opts->gen_hash(ctx->crypto_wrapper, HASH_ALGO_SHA256, claims_buffer,
					    claims_buffer_size, hash);
	if (hash_size >= 16)
		RTLS_DEBUG(
			"evidence user-data field [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
			(size_t)hash_size, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
			hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13],
			hash[14], hash[15]);
	
	// 收集evidence
	enclave_attester_err_t q_err = ctx->attester->opts->collect_evidence(
		ctx->attester, &evidence, ctx->config.cert_algo, hash, hash_size);
	if (q_err != ENCLAVE_ATTESTER_ERR_NONE) {
		free(claims_buffer);
		claims_buffer = NULL;
		return q_err;
	}
	RTLS_DEBUG("evidence.type: '%s'\n", evidence.type);

	/* Prepare cert info for cert generation */
	// 为证书生成准备证书信息
	rats_tls_cert_info_t cert_info = {
		.subject = {
			.organization = (const unsigned char *)"Inclavare Containers",
			.common_name = (const unsigned char *)"RATS-TLS",
		},
		.cert_buf = NULL,
		.cert_len = 0,
		.evidence_buffer = NULL,
		.evidence_buffer_size = 0,
		.endorsements_buffer = NULL,
		.endorsements_buffer_size = 0,
	};

	/* Get DICE evidence buffer */
	/* This check is a workaround for the nullattester.
	 * Note: For nullattester, we do not generate an evidence_buffer. nor do we generate evidence extension.  */
	// 如果是nullattester类型，那就什么也不生成
	if (evidence.type[0] == '\0') {
		RTLS_WARN(
			"evidence type is empty, which is normal only when you are using nullattester.\n");
	  // 非nullattester类型
	} else {
		// 生成cbor格式的evidence_buffer，放到cert_info.evidence_buffer中，内容是evidence_buffer: <tag1>([ evidence->ecdsa.quote(customs-buffer-hash), claims-buffer ])
		enclave_attester_err_t d_ret = dice_generate_evidence_buffer_with_tag(
			&evidence, claims_buffer, claims_buffer_size, &cert_info.evidence_buffer,
			&cert_info.evidence_buffer_size);
		free(claims_buffer);
		claims_buffer = NULL;
		if (d_ret != ENCLAVE_ATTESTER_ERR_NONE) {
			return d_ret;
		}
	}
	RTLS_DEBUG("evidence buffer size: %zu\n", cert_info.evidence_buffer_size);

	/* Collect endorsements if required */
	// 判断是否需要收集endorsements
	if ((evidence.type[0] != '\0' /* skip for nullattester */ &&
	     ctx->config.flags & RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS) &&
	    ctx->attester->opts->collect_endorsements) {
		attestation_endorsement_t endorsements;
		memset(&endorsements, 0, sizeof(attestation_endorsement_t));

		// 收集endorsements
		enclave_attester_err_t q_ret = ctx->attester->opts->collect_endorsements(
			ctx->attester, &evidence, &endorsements);
		if (q_ret != ENCLAVE_ATTESTER_ERR_NONE) {
			RTLS_WARN("failed to collect collateral: %#x\n", q_ret);
			/* Since endorsements are not essential, we tolerate the failure to occur. */
		  // 生成endorsements成功
		} else {
			/* Get DICE endorsements buffer */
			// 生成cbor格式的endorsements_buffer，放到cert_info.endorsements_buffer中，内容是<tag1>([h'<VERSION>', h'<TCB_INFO>', h'<TCB_ISSUER_CHAIN>', h'<CRL_PCK_CERT>', h'<CRL_PCK_PROC_CA>', h'<CRL_ISSUER_CHAIN_PCK_CERT>', h'<QE_ID_INFO>', h'<QE_ID_ISSUER_CHAIN>', h'<CREATION_DATETIME>'])
			enclave_attester_err_t d_ret = dice_generate_endorsements_buffer_with_tag(
				evidence.type, &endorsements, &cert_info.endorsements_buffer,
				&cert_info.endorsements_buffer_size);
			free_endorsements(evidence.type, &endorsements);
			if (d_ret != ENCLAVE_ATTESTER_ERR_NONE) {
				RTLS_ERR("Failed to generate endorsements buffer %#x\n", d_ret);
				return d_ret;
			}
		}
	}
	RTLS_DEBUG("endorsements buffer size: %zu\n", cert_info.endorsements_buffer_size);

	/* Generate the TLS certificate */
	// 生成X509证书
	c_err = ctx->crypto_wrapper->opts->gen_cert(ctx->crypto_wrapper, ctx->config.cert_algo,
						    &cert_info);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Use the TLS certificate and private key for TLS session */
	// 使用 TLS 证书和私钥进行 TLS 会话
	if (privkey_len) {
		tls_wrapper_err_t t_err;

		// printf("privkey_len is [%d], privkey_buf is \n", privkey_len);

		// for (int i = 0; i < privkey_len; i++)
		// {
		// 	printf("%02X", privkey_buf[i]);
		// }
		// printf("\n");

		// 把私钥数据加载到SSL上下文中
		t_err = ctx->tls_wrapper->opts->use_privkey(ctx->tls_wrapper, ctx->config.cert_algo,
							    privkey_buf, privkey_len);
		if (t_err != TLS_WRAPPER_ERR_NONE) {
			if (cert_info.cert_buf)
				free(cert_info.cert_buf);
			return t_err;
<<<<<<< HEAD
		}

=======
        
		// 将X.509证书加载至SSL上下文中，以供SSL/TLS连接使用。
>>>>>>> Added code comments
		t_err = ctx->tls_wrapper->opts->use_cert(ctx->tls_wrapper, &cert_info);
		if (t_err != TLS_WRAPPER_ERR_NONE) {
			if (cert_info.cert_buf)
				free(cert_info.cert_buf);
			return t_err;
		}
	}
	if (cert_info.cert_buf)
		free(cert_info.cert_buf);

	/* Prevent from re-generation of TLS certificate */
	// 标记已经生成 TLS 证书，防止重新生成 TLS 证书
	ctx->flags |= RATS_TLS_CTX_FLAGS_CERT_CREATED;

	return RATS_TLS_ERR_NONE;
}
