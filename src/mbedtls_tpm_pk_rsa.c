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
#include "common.h"

#if (defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C))

#include "mbedtls/pk_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls_tpm_pk.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include <limits.h>
#include <stdint.h>

int tpm_rsa_init(mbedtls_tpm_rsa_context *ctx,
                 bool is_pkcs_v15,
                 ESYS_CONTEXT *esys_ctx)
{
    int ret = 1;
    bool is_equal;
    BYTE nv[strlen(PROVISIONED_MAGIC)];
    BYTE mod[TPM2_MAX_RSA_KEY_BYTES];
    UINT16 nv_len = sizeof(nv);
    UINT32 exponent;
    UINT16 mod_len = sizeof(mod);

    if (!ctx || !esys_ctx) {
        goto out;
    }

    /* Initialize the ESYS_CONTEXT */

    ctx->tpm.esys_ctx = esys_ctx;

    /* Initialize the mbedtls_tpm_rsa_context with default values */

    ctx->tpm.provisioned_handle = TPM2_NV_PROVISIONED_INDEX;
    ctx->tpm.ses_handle = ctx->tpm.parent_handle = TPM2_HANDLE_PARENT;
    ctx->tpm.rsa_handle = TPM2_HANDLE_RSA;
    ctx->tpm.ecp_handle = TPM2_HANDLE_ECP;

    /* Calloc size '+ 1' is to append the null character. */
    if (!(ctx->tpm.provisioned_magic = mbedtls_calloc(1, strlen(PROVISIONED_MAGIC) + 1))) {
        goto out;
    }
    memcpy(ctx->tpm.provisioned_magic, PROVISIONED_MAGIC, strlen(PROVISIONED_MAGIC));

    if (!(ctx->tpm.sh_auth = mbedtls_calloc(1, strlen(TPM2_AUTH_SH) + 1))) {
        goto out_free_tpm_provisioned_magic;
    }
    memcpy(ctx->tpm.sh_auth, TPM2_AUTH_SH, strlen(TPM2_AUTH_SH));

    if (!(ctx->tpm.eh_auth = mbedtls_calloc(1, strlen(TPM2_AUTH_EH) + 1))) {
        goto out_free_tpm_sh_auth;
    }
    memcpy(ctx->tpm.eh_auth, TPM2_AUTH_EH, strlen(TPM2_AUTH_EH));

    if (!(ctx->tpm.lo_auth = mbedtls_calloc(1, strlen(TPM2_AUTH_LO) + 1))) {
        goto out_free_tpm_eh_auth;
    }
    memcpy(ctx->tpm.lo_auth, TPM2_AUTH_LO, strlen(TPM2_AUTH_LO));

    if (!(ctx->tpm.ses_auth = ctx->tpm.parent_auth = mbedtls_calloc(1, strlen(TPM2_AUTH_SRK) + 1))) {
        goto out_free_tpm_lo_auth;
    }
    memcpy(ctx->tpm.parent_auth, TPM2_AUTH_SRK, strlen(TPM2_AUTH_SRK));

    if (!(ctx->tpm.rsa_auth = mbedtls_calloc(1, strlen(TPM2_AUTH_RSA) + 1))) {
        goto out_free_tpm_parent_auth;
    }
    memcpy(ctx->tpm.rsa_auth, TPM2_AUTH_RSA, strlen(TPM2_AUTH_RSA));

    if (!(ctx->tpm.ecp_auth = mbedtls_calloc(1, strlen(TPM2_AUTH_ECP) + 1))) {
        goto out_free_tpm_rsa_auth;
    }
    memcpy(ctx->tpm.ecp_auth, TPM2_AUTH_ECP, strlen(TPM2_AUTH_ECP));

    ctx->tpm.da_max_tries = DA_MAX_TRIES;
    ctx->tpm.da_recovery_time = DA_RECOVERY_TIME;
    ctx->tpm.da_lockout_recovery_time = DA_LOCKOUT_RECOVERY_TIME;

    /* Check if TPM is provisioned by looking into NV magic value */

    if (tss2_nvCompare(ctx->tpm.esys_ctx, ctx->tpm.provisioned_handle, ctx->tpm.provisioned_magic,
                       strlen((const char *)ctx->tpm.provisioned_magic), &is_equal)) {
        goto out_free_tpm_ecp_auth;
    }

    if (is_equal) {
        /* TPM is provisioned */
        goto out_init_mbedtls_rsa_context;
    }

    /* TPM is not provisioned */

    if (tss2_forceClear(ctx->tpm.esys_ctx)) {
        goto out_free_tpm_ecp_auth;
    }

    if (tss2_takeOwnership(ctx->tpm.esys_ctx, ctx->tpm.sh_auth, ctx->tpm.eh_auth, ctx->tpm.lo_auth)) {
        goto out_free_tpm_ecp_auth;
    }

    if (tss2_setDictionaryLockout(ctx->tpm.esys_ctx, ctx->tpm.lo_auth, ctx->tpm.da_max_tries,
                                  ctx->tpm.da_recovery_time, ctx->tpm.da_lockout_recovery_time)) {
        goto out_free_tpm_ecp_auth;
    }

    if (tss2_createPrimaryKey(ctx->tpm.esys_ctx, ctx->tpm.parent_handle, ctx->tpm.sh_auth, ctx->tpm.parent_auth)) {
        goto out_free_tpm_ecp_auth;
    }

    if (tss2_createRsaKey(ctx->tpm.esys_ctx, ctx->tpm.parent_handle, ctx->tpm.parent_auth,
                          ctx->tpm.rsa_handle, ctx->tpm.rsa_auth)) {
        goto out_free_tpm_ecp_auth;
    }

    /* Write the magic value into NV */

    if (tss2_nvDefine(ctx->tpm.esys_ctx, ctx->tpm.provisioned_handle, strlen((const char *)ctx->tpm.provisioned_magic))) {
        goto out_free_tpm_ecp_auth;
    }

    if (tss2_nvWrite(ctx->tpm.esys_ctx, ctx->tpm.provisioned_handle, ctx->tpm.provisioned_magic,
                     strlen((const char *)ctx->tpm.provisioned_magic))) {
        goto out_nv_undefine;
    }

    if (tss2_nvRead(ctx->tpm.esys_ctx, ctx->tpm.provisioned_handle, nv, &nv_len)) {
        goto out_nv_undefine;
    }

    if (memcmp(nv, ctx->tpm.provisioned_magic, strlen((const char *)ctx->tpm.provisioned_magic))) {
        tss2_nvUndefine(ctx->tpm.esys_ctx, ctx->tpm.provisioned_handle);
        goto out_nv_undefine;
    }

    /* Initialize mbedtls_rsa_context */
out_init_mbedtls_rsa_context:

    if (is_pkcs_v15) {
        mbedtls_rsa_init(&ctx->rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
    } else {
        mbedtls_rsa_init(&ctx->rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    }

    if (tss2_readRsaPublicKey(ctx->tpm.esys_ctx, ctx->tpm.rsa_handle, ctx->tpm.ses_handle,
                              ctx->tpm.ses_auth, &exponent, mod, &mod_len)) {
        goto out_mbedtls_rsa_free;
    }

    ctx->rsa.ver = 0;
    if (mbedtls_mpi_read_binary(&ctx->rsa.N, mod, mod_len)) {
        goto out_mbedtls_rsa_free;
    }

    if (exponent != 65537) {
        goto out_mbedtls_rsa_free;
    }

    uint8_t exp[] = {0x1,0x0,0x1}; // exponent 0x65537
    if (mbedtls_mpi_read_binary(&ctx->rsa.E, exp, 3)) {
        goto out_mbedtls_rsa_free;
    }

    ctx->rsa.len = mbedtls_mpi_bitlen(&ctx->rsa.N) / 8;

    if (mbedtls_rsa_check_pubkey(&ctx->rsa)) {
        goto out_mbedtls_rsa_free;
    }

    ret = 0;
    goto out;

out_mbedtls_rsa_free:
    mbedtls_rsa_free(&ctx->rsa);
out_nv_undefine:
    tss2_nvUndefine(ctx->tpm.esys_ctx, ctx->tpm.provisioned_handle);
out_free_tpm_ecp_auth:
    mbedtls_free(ctx->tpm.ecp_auth);
out_free_tpm_rsa_auth:
    mbedtls_free(ctx->tpm.rsa_auth);
out_free_tpm_parent_auth:
    mbedtls_free(ctx->tpm.parent_auth);
out_free_tpm_lo_auth:
    mbedtls_free(ctx->tpm.lo_auth);
out_free_tpm_eh_auth:
    mbedtls_free(ctx->tpm.eh_auth);
out_free_tpm_sh_auth:
    mbedtls_free(ctx->tpm.sh_auth);
out_free_tpm_provisioned_magic:
    mbedtls_free(ctx->tpm.provisioned_magic);
out:
    return ret;
}

void tpm_rsa_free(mbedtls_tpm_rsa_context *ctx)
{
    mbedtls_rsa_free(&ctx->rsa);
    mbedtls_free(ctx->tpm.ecp_auth);
    mbedtls_free(ctx->tpm.rsa_auth);
    mbedtls_free(ctx->tpm.parent_auth);
    mbedtls_free(ctx->tpm.lo_auth);
    mbedtls_free(ctx->tpm.eh_auth);
    mbedtls_free(ctx->tpm.sh_auth);
    mbedtls_free(ctx->tpm.provisioned_magic);
}

static int rsa_pkcs_v15_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_RSA);
}

static int rsa_pkcs_v21_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_RSASSA_PSS);
}

static size_t rsa_get_bitlen(const void *ctx)
{
    const mbedtls_rsa_context *rsa = (const mbedtls_rsa_context *)ctx;
    return (8 * mbedtls_rsa_get_len(rsa));
}

static int rsa_verify(bool is_pkcs_v15,
                      void *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len)
{
    mbedtls_tpm_rsa_context *tpm_rsa_ctx = (mbedtls_tpm_rsa_context *)ctx;
    mbedtls_tpm_context *tpm_ctx = &tpm_rsa_ctx->tpm;
    TPM2_ALG_ID padding;
    int result = 0;

    if (md_alg != MBEDTLS_MD_SHA256 || hash_len != TPM2_SHA256_DIGEST_SIZE) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    if (is_pkcs_v15) {
        padding = TPM2_ALG_RSASSA;
    } else {
        padding = TPM2_ALG_RSAPSS;
    }

    if (tss2_rsaVerify(tpm_ctx->esys_ctx,
                       tpm_ctx->rsa_handle,
                       tpm_ctx->ses_handle,
                       tpm_ctx->ses_auth,
                       padding, TPM2_ALG_SHA256,
                       hash, hash_len,
                       sig, sig_len,
                       &result)) {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    if (result) {
        return 0;
    } else {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }
}

static int rsa_pkcs_v15_verify(void *ctx, mbedtls_md_type_t md_alg,
                               const unsigned char *hash, size_t hash_len,
                               const unsigned char *sig, size_t sig_len)
{
    return rsa_verify(true, ctx, md_alg, hash, hash_len, sig, sig_len);
}

static int rsa_pkcs_v21_verify(void *ctx, mbedtls_md_type_t md_alg,
                               const unsigned char *hash, size_t hash_len,
                               const unsigned char *sig, size_t sig_len)
{
    return rsa_verify(false, ctx, md_alg, hash, hash_len, sig, sig_len);
}

static int rsa_sign(bool is_pkcs_v15,
                    void *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_tpm_rsa_context *tpm_rsa_ctx = (mbedtls_tpm_rsa_context *)ctx;
    TPM2_ALG_ID pad_algo;
    TPM2_ALG_ID hash_algo;
    UINT16 len;

    if (md_alg != MBEDTLS_MD_SHA256 || hash_len != TPM2_SHA256_DIGEST_SIZE) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    if (is_pkcs_v15) {
        pad_algo = TPM2_ALG_RSASSA;
    } else {
        pad_algo = TPM2_ALG_RSAPSS;
    }
    hash_algo = TPM2_ALG_SHA256;

    *sig_len = mbedtls_rsa_get_len(&tpm_rsa_ctx->rsa);
    len = (UINT16)*sig_len;

    if (tss2_rsaSign(tpm_rsa_ctx->tpm.esys_ctx, tpm_rsa_ctx->tpm.rsa_handle,
                     tpm_rsa_ctx->tpm.rsa_auth, tpm_rsa_ctx->tpm.ses_handle,
                     tpm_rsa_ctx->tpm.ses_auth, pad_algo, hash_algo,
                     hash, hash_len, sig, &len)) {
        return MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    }

    *sig_len = (size_t)len;

    return 0;
}

static int rsa_pkcs_v15_sign(void *ctx, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             unsigned char *sig, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return rsa_sign(true, ctx, md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng);
}

static int rsa_pkcs_v21_sign(void *ctx, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             unsigned char *sig, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return rsa_sign(false, ctx, md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng);
}

static int rsa_decrypt(bool is_pkcs_v15, void *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    UINT16 o_len = osize;
    TPM2_ALG_ID pad_algo;
    TPM2_ALG_ID hash_algo;
    mbedtls_tpm_rsa_context *tpm_rsa_ctx = (mbedtls_tpm_rsa_context *)ctx;

    if (is_pkcs_v15) {
        pad_algo = TPM2_ALG_RSAES;
        hash_algo = TPM2_ALG_NULL;
    } else {
        pad_algo = TPM2_ALG_OAEP;
        hash_algo = TPM2_ALG_SHA256;
    }

    if (tss2_decipher(tpm_rsa_ctx->tpm.esys_ctx,
                      tpm_rsa_ctx->tpm.rsa_handle, tpm_rsa_ctx->tpm.rsa_auth,
                      tpm_rsa_ctx->tpm.ses_handle, tpm_rsa_ctx->tpm.ses_auth,
                      pad_algo, hash_algo, input, ilen, output, &o_len)) {
        return MBEDTLS_ERR_RSA_PRIVATE_FAILED;
    }

    *olen = o_len;

    return 0;
}

static int rsa_pkcs_v15_decrypt(void *ctx,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return rsa_decrypt(true, ctx, input, ilen, output, olen, osize, f_rng, p_rng);
}

static int rsa_pkcs_v21_decrypt(void *ctx,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return rsa_decrypt(false, ctx, input, ilen, output, olen, osize, f_rng, p_rng);
}

static int rsa_encrypt(bool is_pkcs_v15, void *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    UINT16 o_len = osize;
    TPM2_ALG_ID pad_algo;
    TPM2_ALG_ID hash_algo;
    mbedtls_tpm_rsa_context *tpm_rsa_ctx = (mbedtls_tpm_rsa_context *)ctx;

    if (is_pkcs_v15) {
        pad_algo = TPM2_ALG_RSAES;
        hash_algo = TPM2_ALG_NULL;
    } else {
        pad_algo = TPM2_ALG_OAEP;
        hash_algo = TPM2_ALG_SHA256;
    }

    if (tss2_cipher(tpm_rsa_ctx->tpm.esys_ctx, tpm_rsa_ctx->tpm.rsa_handle,
                    tpm_rsa_ctx->tpm.ses_handle, tpm_rsa_ctx->tpm.ses_auth,
                    pad_algo, hash_algo, input, ilen, output, &o_len)) {
        return MBEDTLS_ERR_RSA_PUBLIC_FAILED;
    }

    *olen = o_len;

    return 0;
}

static int rsa_pkcs_v15_encrypt(void *ctx,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return rsa_encrypt(true, ctx, input, ilen, output, olen, osize, f_rng, p_rng);
}

static int rsa_pkcs_v21_encrypt(void *ctx,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return rsa_encrypt(false, ctx, input, ilen, output, olen, osize, f_rng, p_rng);
}

static int rsa_check_pair(bool is_pkcs_v15, const void *pub, const void *prv)
{
    mbedtls_rsa_context *rsa_pub_ctx = (mbedtls_rsa_context *)pub;
    mbedtls_tpm_rsa_context *tpm_rsa_ctx = (mbedtls_tpm_rsa_context *)prv;
    mbedtls_tpm_context *tpm_ctx = &tpm_rsa_ctx->tpm;
    BYTE hash[TPM2_SHA256_DIGEST_SIZE];
    unsigned char sig[TPM2_MAX_RSA_KEY_BYTES];
    UINT16 hash_len = sizeof(hash);
    size_t sig_len;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;

    if (tss2_getRandom(tpm_ctx->esys_ctx, tpm_ctx->ses_handle,
                       tpm_ctx->ses_auth, hash, &hash_len)
        || hash_len != sizeof(hash)) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    if (rsa_sign(is_pkcs_v15, (void *)prv, md_alg, hash, hash_len,
                 sig, &sig_len, NULL, NULL)) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    /* Redundancy check */
    /*if (rsa_verify(is_pkcs_v15, (void *)prv, md_alg, hash, hash_len,
                   sig, sig_len)) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }*/

    if(mbedtls_rsa_pkcs1_verify(rsa_pub_ctx, NULL, NULL,
                                MBEDTLS_RSA_PUBLIC, md_alg,
                                hash_len, hash, sig)) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }


    return 0;
}

static int rsa_pkcs_v15_check_pair(const void *pub, const void *prv)
{
    return rsa_check_pair(true, pub, prv);
}

static int rsa_pkcs_v21_check_pair(const void *pub, const void *prv)
{
    return rsa_check_pair(false, pub, prv);
}

static void *rsa_alloc(void)
{
    return mbedtls_calloc(1, sizeof(mbedtls_tpm_rsa_context));
}

static void rsa_free(void *ctx)
{
    mbedtls_free(ctx);
}

static void rsa_debug(const void *ctx, mbedtls_pk_debug_item *items)
{
    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &(((mbedtls_rsa_context *)ctx)->N);

    items++;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &(((mbedtls_rsa_context *)ctx)->E);
}

const mbedtls_pk_info_t tpm_rsa_pkcs_v15_info = {
    MBEDTLS_PK_RSA,
    "TPM RSA_PKCS_V15",
    rsa_get_bitlen,
    rsa_pkcs_v15_can_do,
    rsa_pkcs_v15_verify,
    rsa_pkcs_v15_sign,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_pkcs_v15_decrypt,
    rsa_pkcs_v15_encrypt,
    rsa_pkcs_v15_check_pair,
    rsa_alloc,
    rsa_free,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_debug,
};

const mbedtls_pk_info_t tpm_rsa_pkcs_v21_info = {
    MBEDTLS_PK_RSASSA_PSS,
    "TPM RSA_PKCS_V21",
    rsa_get_bitlen,
    rsa_pkcs_v21_can_do,
    rsa_pkcs_v21_verify,
    rsa_pkcs_v21_sign,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_pkcs_v21_decrypt,
    rsa_pkcs_v21_encrypt,
    rsa_pkcs_v21_check_pair,
    rsa_alloc,
    rsa_free,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_debug,
};

#endif
