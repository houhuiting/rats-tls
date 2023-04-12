/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/crypto_wrapper.h"

// crypto_wrappers_opts数组用于存放所有可注册的crypto_wrapper的选项信息
crypto_wrapper_opts_t *crypto_wrappers_opts[CRYPTO_WRAPPER_TYPE_MAX];
// 可注册crypto_wrapper的数量
unsigned int registerd_crypto_wrapper_nums;

//将所有pre_init成功的crypto_wrapper实例crypto_wrapper_ctx_t结构体，放到crypto_wrappers_ctx数组中
crypto_wrapper_ctx_t *crypto_wrappers_ctx[CRYPTO_WRAPPER_TYPE_MAX];
unsigned int crypto_wrappers_nums;
