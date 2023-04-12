/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include "internal/core.h"

// 设置用户自定义的回调函数
// 将回调函数指针赋值给rtls_core_context_t结构体的rats_tls_callback_t类型的user_callback
rats_tls_err_t rats_tls_set_verification_callback(rats_tls_handle *handle, rats_tls_callback_t cb)
{
	RTLS_DEBUG("set user verification callback handle: %p, cb %p\n", handle, cb);

	(*handle)->user_callback = cb;

	return RATS_TLS_ERR_NONE;
}
