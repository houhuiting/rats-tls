/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_TLS_HASH_H
#define _RATS_TLS_HASH_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_HASH_SIZE 32
#define SHA384_HASH_SIZE 48
#define SHA512_HASH_SIZE 64
#define MAX_HASH_SIZE	 SHA512_HASH_SIZE

/* https://www.iana.org/assignments/named-information/named-information.xhtml */
typedef enum {
	HASH_ALGO_RESERVED = 0,
	HASH_ALGO_SHA256 = 1,
	HASH_ALGO_SHA384 = 7,
	HASH_ALGO_SHA512 = 8,
} hash_algo_t;


#endif /* _RATS_TLS_HASH_H */
