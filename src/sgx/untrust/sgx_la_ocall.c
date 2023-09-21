/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <rats-tls/verifier.h>
#include "sgx_error.h"
#include "sgx_quote_3.h"
#include "sgx_dcap_ql_wrapper.h"
