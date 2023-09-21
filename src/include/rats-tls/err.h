/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_ERR_H
#define _ENCLAVE_ERR_H

/*
 * The error code definition.
 *
 * Rats TLS specific error code is a 32-bit signed integer with the follow layout:
 * 1  ccc sssss x...x
 * ^  ^   ^   ^ ^   ^
 * 31 30  27 23 22  0
 *
 * Bit 31: always 1, indicating a negative value.
 * Bit 30-28: error code class
 * Bit 27-23: error code sub-class (if any)
 * Bit 22-00: sub-class specific error codes
 */

#define ERR_CODE_CLASS_SHIFT	28
#define ERR_CODE_SUBCLASS_SHIFT 23
#define ERR_CODE_CLASS_MASK	0x70000000
#define ERR_CODE_SUBCLASS_MASK	0x0f800000
#define ERR_CODE_ERROR_MASK	((1 << ERR_CODE_SUBCLASS_SHIFT) - 1)
#define ERR_CODE_NAGATIVE	(1 << 31)

/* The error code class */
#define RATS_TLS_ERR_BASE	  (0 << ERR_CODE_CLASS_SHIFT)
#define TLS_WRAPPER_ERR_BASE	  (1 << ERR_CODE_CLASS_SHIFT)
#define ENCLAVE_ATTESTER_ERR_BASE (2 << ERR_CODE_CLASS_SHIFT)
#define ENCLAVE_VERIFIER_ERR_BASE (3 << ERR_CODE_CLASS_SHIFT)
#define CRYPTO_WRAPPER_ERR_BASE	  (4 << ERR_CODE_CLASS_SHIFT)

/* The base of error code used by sgx-ecdsa */
#define SGX_ECDSA_ERR_BASE (0 << ERR_CODE_SUBCLASS_SHIFT)

/* The base of error code used by sgx-la */
#define SGX_LA_ERR_BASE (0 << ERR_CODE_SUBCLASS_SHIFT)

/* The base of error code used by openssl */
#define OPENSSL_ERR_BASE (1 << ERR_CODE_SUBCLASS_SHIFT)

// Error code used to construct TLS Wrapper instance
#define __TLS_WRAPPER_ERR_CODE(base, err)                                                        \
	(((TLS_WRAPPER_ERR_BASE + (base)) & ERR_CODE_CLASS_MASK) | ((err)&ERR_CODE_ERROR_MASK) | \
	 ERR_CODE_NAGATIVE)

#define OPENSSL_ERR_CODE(err) __TLS_WRAPPER_ERR_CODE(OPENSSL_ERR_BASE, err)

#define __CRYPTO_WRAPPER_ERR_CODE(base, err)                          \
	(((CRYPTO_WRAPPER_ERR_BASE + (base)) & ERR_CODE_CLASS_MASK) | \
	 ((err)&ERR_CODE_ERROR_MASK) | ERR_CODE_NAGATIVE)

#define __ENCLAVE_ATTESTER_ERR_CODE(base, err)                          \
	(((ENCLAVE_ATTESTER_ERR_BASE + (base)) & ERR_CODE_CLASS_MASK) | \
	 ((err)&ERR_CODE_ERROR_MASK) | ERR_CODE_NAGATIVE)

#define SGX_ECDSA_ATTESTER_ERR_CODE(err) __ENCLAVE_ATTESTER_ERR_CODE(SGX_ECDSA_ERR_BASE, err)

#define SGX_LA_ATTESTER_ERR_CODE(err) __ENCLAVE_ATTESTER_ERR_CODE(SGX_LA_ERR_BASE, err)

#define __ENCLAVE_VERIFIER_ERR_CODE(base, err)                          \
	(((ENCLAVE_VERIFIER_ERR_BASE + (base)) & ERR_CODE_CLASS_MASK) | \
	 ((err)&ERR_CODE_ERROR_MASK) | ERR_CODE_NAGATIVE)

#define SGX_ECDSA_VERIFIER_ERR_CODE(err) __ENCLAVE_VERIFIER_ERR_CODE(SGX_ECDSA_ERR_BASE, err)

#define SGX_LA_VERIFIER_ERR_CODE(err) __ENCLAVE_VERIFIER_ERR_CODE(SGX_LA_ERR_BASE, err)

typedef enum {
	RATS_TLS_ERR_NONE = RATS_TLS_ERR_BASE,
	RATS_TLS_ERR_UNKNOWN,
	RATS_TLS_ERR_INVALID,
	RATS_TLS_ERR_NO_MEM,
	RATS_TLS_ERR_NOT_REGISTERED,
	RATS_TLS_ERR_LOAD_CRYPTO_WRAPPERS,
	RATS_TLS_ERR_LOAD_TLS_WRAPPERS,
	RATS_TLS_ERR_LOAD_ENCLAVE_ATTESTERS,
	RATS_TLS_ERR_LOAD_ENCLAVE_VERIFIERS,
	RATS_TLS_ERR_DLOPEN,
	RATS_TLS_ERR_INIT,
	RATS_TLS_ERR_UNSUPPORTED_CERT_ALGO,
	RATS_TLS_ERR_NO_NAME,
} rats_tls_err_t;

typedef enum {
	TLS_WRAPPER_ERR_NONE = TLS_WRAPPER_ERR_BASE,
	TLS_WRAPPER_ERR_NO_MEM,
	/* The specified TLS library does not exist */
	TLS_WRAPPER_ERR_NOT_FOUND,
	TLS_WRAPPER_ERR_INVALID,
	TLS_WRAPPER_ERR_TRANSMIT,
	TLS_WRAPPER_ERR_RECEIVE,
	TLS_WRAPPER_ERR_UNSUPPORTED_QUOTE,
	TLS_WRAPPER_ERR_PRIV_KEY,
	TLS_WRAPPER_ERR_CERT,
	TLS_WRAPPER_ERR_UNKNOWN,
} tls_wrapper_err_t;


#endif /* _ENCLAVE_ERR_H */
