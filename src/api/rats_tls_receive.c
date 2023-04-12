/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/api.h>
#include <rats-tls/log.h>

#include "internal/core.h"

// 当Rats-TLS 可信信道建立成功之后，客户端和服务端直接就可以通过Rats TLS API rats_tls_receive()进行安全数据的传输（接收数据）
// buf是接收到的数据，buf_size是数据大小
rats_tls_err_t rats_tls_receive(rats_tls_handle handle, void *buf, size_t *buf_size)
{
	rtls_core_context_t *ctx = (rtls_core_context_t *)handle;

	RTLS_DEBUG("handle %p, buf %p, buf_size %p (%zu-byte)\n", ctx, buf, buf_size, *buf_size);

	if (!handle || !handle->tls_wrapper || !handle->tls_wrapper->opts ||
	    !handle->tls_wrapper->opts->receive || !buf || !buf_size)
		return -RATS_TLS_ERR_INVALID;

	// 调用TLS Wrapper实例的receive方法来发送数据
	tls_wrapper_err_t err =
		handle->tls_wrapper->opts->receive(handle->tls_wrapper, buf, buf_size);
	if (err != TLS_WRAPPER_ERR_NONE)
		return -RATS_TLS_ERR_INVALID;

	return RATS_TLS_ERR_NONE;
}
