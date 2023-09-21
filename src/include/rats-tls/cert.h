/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_CERT_H
#define _ENCLAVE_CERT_H

#define SGX_ECDSA_QUOTE_SZ 8192
#define TDX_ECDSA_QUOTE_SZ 8192
#define TDEL_INFO_SZ	   56
#define TDEL_DATA_SZ	   65536

typedef struct {
	const unsigned char *organization;
	const unsigned char *organization_unit;
	const unsigned char *common_name;
} cert_subject_t;


typedef struct {
	cert_subject_t subject;
	unsigned int cert_len;
	uint8_t *cert_buf;
	uint8_t *evidence_buffer;
	size_t evidence_buffer_size;
	uint8_t *endorsements_buffer;
	size_t endorsements_buffer_size;
} rats_tls_cert_info_t;

#endif
