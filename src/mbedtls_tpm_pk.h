/**
 * MIT License
 *
 * Copyright (c) 2023 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

#ifndef PK_TPM_H
#define PK_TPM_H

#include <stdbool.h>

#include "common.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include "tss2_util.h"

#define TPM2_NV_PROVISIONED_INDEX   0x01000321
#define PROVISIONED_MAGIC           "TPM is Provisioned"

#define TPM2_HANDLE_PARENT          0x8100beef
#define TPM2_HANDLE_RSA             0x8100cafe
#define TPM2_HANDLE_ECP             0x8100bead

#define DA_MAX_TRIES                32   /* 32 retries before entering lockout. */
#define DA_RECOVERY_TIME            5    /* Every 5 secs recover 1 retry. */
#define DA_LOCKOUT_RECOVERY_TIME    300  /* The lockout duration (300 secs) */

#define TPM2_AUTH_SH            "owner123"
#define TPM2_AUTH_EH            "endorsement123"
#define TPM2_AUTH_LO            "lockout123"
#define TPM2_AUTH_SRK           "srk123"
#define TPM2_AUTH_RSA           "rsaleaf123"
#define TPM2_AUTH_ECP           "ecleaf123"

#if defined(MBEDTLS_RSA_C)

typedef struct {
    ESYS_CONTEXT  *esys_ctx;
    TPM2_HANDLE   provisioned_handle;
    TPM2_HANDLE   parent_handle;
    TPM2_HANDLE   rsa_handle;
    TPM2_HANDLE   ecp_handle;
    TPM2_HANDLE   ses_handle;
    BYTE          *provisioned_magic;
    char          *sh_auth; /* Storage hierarchy auth value */
    char          *eh_auth; /* Endorsement hierarchy auth value */
    char          *lo_auth; /* Lockout auth value */
    char          *parent_auth;
    char          *rsa_auth;
    char          *ecp_auth;
    char          *ses_auth;
    UINT32        da_max_tries;
    UINT32        da_recovery_time;
    UINT32        da_lockout_recovery_time;
} mbedtls_tpm_context;

typedef struct {
    mbedtls_ecp_keypair ecp;
    mbedtls_tpm_context tpm;
} mbedtls_tpm_ecp_context;

typedef struct {
    mbedtls_rsa_context rsa;
    mbedtls_tpm_context tpm;
} mbedtls_tpm_rsa_context;

extern const mbedtls_pk_info_t tpm_ecp_info;
extern const mbedtls_pk_info_t tpm_rsa_pkcs_v15_info;
extern const mbedtls_pk_info_t tpm_rsa_pkcs_v21_info;

int tpm_ecp_init(mbedtls_tpm_ecp_context *, ESYS_CONTEXT *); /* This will also provision the TPM with ECP key when it is necessary */
void tpm_ecp_free(mbedtls_tpm_ecp_context *);

int tpm_rsa_init(mbedtls_tpm_rsa_context *, bool, ESYS_CONTEXT *); /* This will also provision the TPM with RSA key when it is necessary */
void tpm_rsa_free(mbedtls_tpm_rsa_context *);

int tpm_entropy_init(mbedtls_tpm_context *,
                     mbedtls_ctr_drbg_context *,
                     mbedtls_entropy_context *);

int tpm_open(ESYS_CONTEXT **, const char *);
void tpm_release(ESYS_CONTEXT **);

int tpm_factory_reset(ESYS_CONTEXT *);

#endif

#endif
