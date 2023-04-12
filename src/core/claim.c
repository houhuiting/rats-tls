/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/claim.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>

static void _free_claim(claim_t *claim)
{
	free(claim->name);
	free(claim->value);
}

// 释放claims
void free_claims_list(claim_t *claims, size_t claims_length)
{
	if (!claims)
		return;

	for (size_t j = 0; j < claims_length; j++)
		_free_claim(&claims[j]);

	free(claims);
}

// 添加一个claim元素，把结果放到claim指针中
int _add_claim(claim_t *claim, const void *name, size_t name_size, const void *value,
	       size_t value_size)
{
	claim->name = (char *)malloc(name_size);
	if (claim->name == NULL)
		return 1;
	memcpy(claim->name, name, name_size);

	claim->value = (uint8_t *)malloc(value_size);
	if (claim->value == NULL) {
		free(claim->name);
		claim->name = NULL;
		return 1;
	}
	memcpy(claim->value, value, value_size);
	claim->value_size = value_size;

	return 0;
}

// 拷贝claims列表
claim_t *clone_claims_list(claim_t *claims, size_t claims_length)
{
	if (!claims_length)
		return NULL;
	// 初始化一下输出指针claims_out
	claim_t *claims_out = (claim_t *)malloc(claims_length * sizeof(claim_t));
	if (!claims_out)
		return NULL;
	size_t i = 0;
	// 做一个循环，将claims指针指向的列表，添加到claims_out列表中
	for (; i < claims_length; i++) {
		if (_add_claim(&claims_out[i], claims[i].name, strlen(claims[i].name) + 1,
			       claims[i].value, claims[i].value_size)) {
			break;
		}
	}
	// 如果失败了
	if (i != claims_length) { /* failed */
		for (size_t j = 0; j < i; j++) {
			_free_claim(&claims_out[j]);
		}
		free(claims_out);
		return NULL;
	}
	return claims_out;
}
