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

#if (defined(MBEDTLS_PK_C) && defined(MBEDTLS_ECP_C))

#include "mbedtls/asn1write.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/error.h"
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

static size_t ecp_get_bitlen(const void *ctx);

int tpm_ecp_init(mbedtls_tpm_ecp_context *ctx, ESYS_CONTEXT *esys_ctx)
{
    int ret = 1;
    bool is_equal;
    BYTE ecp_xy[MBEDTLS_ECP_MAX_BYTES + 1];
    BYTE nv[strlen(PROVISIONED_MAGIC)];
    UINT16 nv_len = sizeof(nv);
    UINT16 ecp_x_len, ecp_y_len;
    size_t curve_bytes;

    if (!ctx || !esys_ctx) {
        goto out;
    }

    /* Initialize the ESYS_CONTEXT */

    ctx->tpm.esys_ctx = esys_ctx;

    /* Initialize the mbedtls_tpm_ecp_context with default values */

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
        goto out_init_mbedtls_ecp_context;
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

    if (tss2_createEcpKey(ctx->tpm.esys_ctx, ctx->tpm.parent_handle, ctx->tpm.parent_auth,
                          ctx->tpm.ecp_handle, ctx->tpm.ecp_auth)) {
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

    /* Initialize mbedtls_ecp_context (SECP256R1) */
out_init_mbedtls_ecp_context:

    mbedtls_ecp_keypair_init(&ctx->ecp);
    mbedtls_ecp_point_init(&ctx->ecp.Q);
    mbedtls_ecp_group_init(&ctx->ecp.grp);

    if (mbedtls_ecp_group_load(&ctx->ecp.grp, MBEDTLS_ECP_DP_SECP256R1)) {
        goto out_mbedtls_ecp_free;
    }

    curve_bytes = ecp_get_bitlen(ctx) / 8;
    ecp_xy[0] = 0x04; /* Uncompressed public key format */
    if (tss2_readEcpPublicKey(ctx->tpm.esys_ctx, ctx->tpm.ecp_handle, ctx->tpm.ses_handle,
                              ctx->tpm.ses_auth, &ecp_xy[1], &ecp_x_len, &ecp_xy[33], &ecp_y_len)
        || ecp_x_len != curve_bytes || ecp_y_len != curve_bytes) {
        goto out_mbedtls_ecp_free;
    }

    mbedtls_ecp_point_read_binary(&ctx->ecp.grp, &ctx->ecp.Q, ecp_xy, ecp_x_len + ecp_y_len + 1);

    ret = 0;
    goto out;

out_mbedtls_ecp_free:
    mbedtls_ecp_group_free(&ctx->ecp.grp);
    mbedtls_ecp_point_free(&ctx->ecp.Q);
    mbedtls_ecp_keypair_free(&ctx->ecp);
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

void tpm_ecp_free(mbedtls_tpm_ecp_context *ctx)
{
    mbedtls_ecp_keypair_free(&ctx->ecp);
    mbedtls_free(ctx->tpm.ecp_auth);
    mbedtls_free(ctx->tpm.rsa_auth);
    mbedtls_free(ctx->tpm.parent_auth);
    mbedtls_free(ctx->tpm.lo_auth);
    mbedtls_free(ctx->tpm.eh_auth);
    mbedtls_free(ctx->tpm.sh_auth);
    mbedtls_free(ctx->tpm.provisioned_magic);
}

static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s,
                                   unsigned char *sig, size_t *slen)
{
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof(buf);
    int asn_ret = 0, asn_len = 0;

    if ((asn_ret = mbedtls_asn1_write_mpi(&p, buf, s)) <= 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    } else {
        asn_len += asn_ret;
    }

    if ((asn_ret = mbedtls_asn1_write_mpi(&p, buf, r)) <= 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    } else {
        asn_len += asn_ret;
    }

    if ((asn_ret = mbedtls_asn1_write_len(&p, buf, asn_len)) <= 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    } else {
        asn_len += asn_ret;
    }

    if ((asn_ret = mbedtls_asn1_write_tag(&p, buf,
                                          MBEDTLS_ASN1_CONSTRUCTED
                                          | MBEDTLS_ASN1_SEQUENCE)) <= 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    } else {
        asn_len += asn_ret;
    }

    memcpy(sig, p, asn_len);
    *slen = asn_len;

    return 0;
}

static int ecdsa_asn1_to_signature(mbedtls_mpi *r, mbedtls_mpi *s,
                                   const unsigned char *sig, const size_t slen)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    unsigned char *p = (unsigned char *)sig;
    const unsigned char *end = sig + slen;
    size_t len = 0;

    if (mbedtls_asn1_get_tag(&p, end, &len,
                             MBEDTLS_ASN1_CONSTRUCTED
                             | MBEDTLS_ASN1_SEQUENCE)) {
        goto out;
    }

    if (p + len != end) {
        goto out;
    }

    if (mbedtls_asn1_get_mpi(&p, end, r)
        || mbedtls_asn1_get_mpi(&p, end, s)) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}
static size_t ecp_get_bitlen(const void *ctx)
{
    mbedtls_tpm_ecp_context *tpm_ecp_ctx = (mbedtls_tpm_ecp_context *)ctx;

    return tpm_ecp_ctx->ecp.grp.pbits;
}

static int ecp_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_ECKEY
            || type == MBEDTLS_PK_ECKEY_DH
            || type == MBEDTLS_PK_ECDSA);
}

static int ecp_verify(void *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
    BYTE sig_r[TPM2_MAX_ECC_KEY_BYTES], sig_s[TPM2_MAX_ECC_KEY_BYTES];
    mbedtls_tpm_ecp_context *tpm_ecp_ctx = (mbedtls_tpm_ecp_context *)ctx;
    mbedtls_mpi r, s;
    TPM2_ALG_ID sig_scheme = TPM2_ALG_ECDSA;
    TPM2_ALG_ID hash_algo = TPM2_ALG_SHA256;
    size_t curve_bytes;
    UINT16 sig_r_len, sig_s_len;
    int result = 0;

    if (md_alg != MBEDTLS_MD_SHA256 || hash_len != TPM2_SHA256_DIGEST_SIZE) {
        ret += MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
        goto out;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (ecdsa_asn1_to_signature(&r, &s, sig, sig_len)) {
        goto out;
    }

    curve_bytes = ecp_get_bitlen(ctx) / 8;
    sig_r_len = sig_s_len = curve_bytes;

    if (mbedtls_mpi_write_binary(&r, sig_r, sig_r_len)
        || mbedtls_mpi_write_binary(&s, sig_s, sig_s_len)) {
        goto out_mbedtls_mpi_free;
    }

    if (tss2_ecpVerify(tpm_ecp_ctx->tpm.esys_ctx, tpm_ecp_ctx->tpm.ecp_handle,
                       tpm_ecp_ctx->tpm.ses_handle, tpm_ecp_ctx->tpm.ses_auth,
                       sig_scheme, hash_algo, hash, hash_len,
                       sig_r, sig_r_len, sig_s, sig_s_len, &result)) {
        goto out;
    }

    if (result) {
        ret = 0;
    }

out_mbedtls_mpi_free:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
out:
    return ret;
}

static int ecp_sign(void *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    size_t curve_bytes;
    mbedtls_mpi r, s;
    BYTE sig_r[TPM2_MAX_ECC_KEY_BYTES], sig_s[TPM2_MAX_ECC_KEY_BYTES];
    UINT16 sig_r_len, sig_s_len;
    mbedtls_tpm_ecp_context *tpm_ecp_ctx = (mbedtls_tpm_ecp_context *)ctx;
    TPM2_ALG_ID sig_scheme = TPM2_ALG_ECDSA;
    TPM2_ALG_ID hash_algo = TPM2_ALG_SHA256;

    if (md_alg != MBEDTLS_MD_SHA256 || hash_len != TPM2_SHA256_DIGEST_SIZE) {
        ret = MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
        goto out;
    }

    curve_bytes = ecp_get_bitlen(ctx) / 8;
    sig_r_len = sig_s_len = curve_bytes;

    if (tss2_ecpSign(tpm_ecp_ctx->tpm.esys_ctx, tpm_ecp_ctx->tpm.ecp_handle,
                     tpm_ecp_ctx->tpm.ecp_auth, tpm_ecp_ctx->tpm.ses_handle,
                     tpm_ecp_ctx->tpm.ses_auth, sig_scheme, hash_algo,
                     hash, hash_len, sig_r, &sig_r_len, sig_s, &sig_s_len)) {
        goto out;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_mpi_read_binary(&r, sig_r, sig_r_len)
        || mbedtls_mpi_read_binary(&s, sig_s, sig_s_len)
        || ecdsa_signature_to_asn1(&r, &s, sig, sig_len)) {
        goto out_mpi_free;
    }

    ret = 0;
out_mpi_free:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
out:
    return ret;
}

static int ecp_check_pair(const void *pub, const void *prv)
{
    mbedtls_tpm_ecp_context *tpm_ecp_ctx = (mbedtls_tpm_ecp_context *)prv;
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    mbedtls_ecdsa_context ecdsa;
    BYTE hash[TPM2_SHA256_DIGEST_SIZE];
    UINT16 hash_len = sizeof(hash);
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = MBEDTLS_ECDSA_MAX_LEN;

    if (tss2_getRandom(tpm_ecp_ctx->tpm.esys_ctx, tpm_ecp_ctx->tpm.ses_handle,
                       tpm_ecp_ctx->tpm.ses_auth, hash, &hash_len)
        || hash_len != sizeof(hash)) {
        goto out;
    }

    if (ecp_sign((void *)prv, MBEDTLS_MD_SHA256, hash, hash_len,
                 sig, &sig_len, NULL, NULL)) {
        goto out;
    }

    mbedtls_ecdsa_init(&ecdsa);

    if ((ret = mbedtls_ecdsa_from_keypair(&ecdsa, (const mbedtls_ecp_keypair *)pub))) {
        goto out_free_ecdsa_context;
    }

    if ((ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, sizeof(hash), sig, sig_len))) {
        goto out_free_ecdsa_context;
    }

    ret = 0;
out_free_ecdsa_context:
    mbedtls_ecdsa_free(&ecdsa);
out:
    return ret;
}

static void *ecp_alloc(void)
{
    return mbedtls_calloc(1, sizeof(mbedtls_tpm_ecp_context));
}

static void ecp_free(void *ctx)
{
    mbedtls_free(ctx);
}

static void ecp_debug(const void *ctx, mbedtls_pk_debug_item *items)
{
    items->type = MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &(((mbedtls_ecp_keypair *)ctx)->Q);
}

const mbedtls_pk_info_t tpm_ecp_info = {
    MBEDTLS_PK_ECKEY,
    "TPM ECKEY",
    ecp_get_bitlen,
    ecp_can_do,
    ecp_verify,
    ecp_sign,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    ecp_check_pair,
    ecp_alloc,
    ecp_free,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    ecp_debug,
};

#endif
