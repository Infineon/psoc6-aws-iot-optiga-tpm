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
#include "mbedtls_examples.h"
#include "stdio.h"
#include "string.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls_tpm_pk.h"

#ifndef TCTI_NAME_CONF
#define TCTI_NAME_CONF NULL /* Auto detect */
#endif

#define PRINT_MBEDTLS_ERR(e) \
    mbedtls_strerror(e, err_buf, sizeof(err_buf)); \
    PRINT("MbedTLS library error: %s\n", err_buf);

static char err_buf[256];

int tpm_unprovision(void)
{
    int ret = 1;
    ESYS_CONTEXT *ctx;

    if (tpm_open(&ctx, TCTI_NAME_CONF)) {
        goto out;
    }

    if (tpm_factory_reset(ctx)) {
        goto out_tpm_release;
    }

    ret = 0;
out_tpm_release:
    tpm_release(&ctx);
out:
    return ret;
}

int x509_csr_crt(mbedtls_pk_context *pk,
         mbedtls_ctr_drbg_context *drbg_ctx,
         mbedtls_entropy_context *entropy_ctx)
{
    int err_num, ret = 1;

    mbedtls_x509write_csr x509write_csr;
    mbedtls_mpi serial;
    size_t csr_buf_len;
    unsigned char csr_buf[4096];
    const char *subject_name = "C=SG,ST=SG,L=8 Kallang Sector,O=Infineon Technologies,OU=CSS,CN=TPM Certificate";

    mbedtls_x509write_cert x509write_crt;
    mbedtls_x509_csr x509_csr;
    int san_ret, san_len;
    size_t crt_buf_len;
    char dn[256];
    unsigned char san_buf[512];
    unsigned char crt_buf[4096];
    unsigned char *san_ptr = san_buf + sizeof(san_buf);
    const char *issuer_name = "C=SG,O=IFX,CN=IFX";

    /* Generates a Certificate Signing Request */

    mbedtls_x509write_csr_init(&x509write_csr);
    mbedtls_x509write_csr_set_key(&x509write_csr, pk);
    mbedtls_x509write_csr_set_md_alg(&x509write_csr, MBEDTLS_MD_SHA256);

    if ((err_num = mbedtls_x509write_csr_set_subject_name(&x509write_csr, subject_name))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_mbedtls_x509write_csr_free;
    }

    if ((err_num = mbedtls_x509write_csr_pem(&x509write_csr, csr_buf, sizeof(csr_buf),
                                             mbedtls_ctr_drbg_random, &drbg_ctx))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_mbedtls_x509write_csr_free;
    }

    PRINT("Generated a CSR in PEM encoding:\r\n");
    PRINT_HEADLESS("%s", csr_buf);
    PRINT_HEADLESS("\r\n");

    /* Generates a self-signed certificate */

    if ((csr_buf_len = mbedtls_x509write_csr_der(&x509write_csr, csr_buf, sizeof(csr_buf),
                                                 mbedtls_ctr_drbg_random, &drbg_ctx)) <= 0) {
        PRINT_MBEDTLS_ERR(csr_buf_len);
        goto out_mbedtls_x509write_csr_free;
    }

    mbedtls_x509write_crt_init(&x509write_crt);
    mbedtls_x509_csr_init(&x509_csr);

    if ((err_num = mbedtls_x509_csr_parse_der(&x509_csr, csr_buf + sizeof(csr_buf) - csr_buf_len, csr_buf_len))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_mbedtls_x509write_crt_free;
    }

    if ((err_num = mbedtls_x509_dn_gets(dn, sizeof(dn), &x509_csr.subject)) <= 0) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_mbedtls_x509write_crt_free;
    }

    mbedtls_mpi_init(&serial);
    mbedtls_mpi_read_string(&serial, 10, "1");
    mbedtls_x509write_crt_set_serial(&x509write_crt, &serial);

    mbedtls_x509write_crt_set_subject_name(&x509write_crt, dn);
    mbedtls_x509write_crt_set_subject_key(&x509write_crt, &x509_csr.pk);

    mbedtls_x509write_crt_set_issuer_name(&x509write_crt, issuer_name);
    mbedtls_x509write_crt_set_issuer_key(&x509write_crt, pk);

    mbedtls_x509write_crt_set_md_alg(&x509write_crt, MBEDTLS_MD_SHA256);

    mbedtls_x509write_crt_set_validity(&x509write_crt, "20190102235959", "21001231235959");

    mbedtls_x509write_crt_set_key_usage(&x509write_crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE
                                        | MBEDTLS_X509_KU_NON_REPUDIATION
                                        | MBEDTLS_X509_KU_KEY_ENCIPHERMENT
                                        | MBEDTLS_X509_KU_DATA_ENCIPHERMENT
                                        | MBEDTLS_X509_KU_CRL_SIGN);

    /* Set X509v3 extensions */

    mbedtls_x509write_crt_set_subject_key_identifier(&x509write_crt);
    mbedtls_x509write_crt_set_authority_key_identifier(&x509write_crt);
    mbedtls_x509write_crt_set_basic_constraints(&x509write_crt, 0, -1); /* Set to true if it is a CA certificate */

    { /* Set Subject Alternative Name (SAN) */
        memset(san_buf, 0, sizeof(san_buf));
        san_len = 0;

        const char san_dns1[] = "localhost";
        if ((san_ret = mbedtls_asn1_write_tagged_string(&san_ptr, san_buf,
                                                        (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME),
                                                        san_dns1, sizeof(san_dns1))) <= 0) {
            goto out_mbedtls_mpi_free;
        } else {
            san_len += san_ret;
        }

        const char san_dns2[] = "infineon.com";
        if ((san_ret = mbedtls_asn1_write_tagged_string(&san_ptr, san_buf,
                                                        (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME),
                                                        san_dns2, sizeof(san_dns2))) <= 0) {
            goto out_mbedtls_mpi_free;
        } else {
            san_len += san_ret;
        }

        const char san_ip1[] = {0x00, 0x00, 0x00, 0x00}; /* Ip address: 0.0.0.0 */
        if ((san_ret = mbedtls_asn1_write_tagged_string(&san_ptr, san_buf,
                                                        (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_IP_ADDRESS),
                                                        san_ip1, sizeof(san_ip1))) <= 0) {
            goto out_mbedtls_mpi_free;
        } else {
            san_len += san_ret;
        }

        const char san_ip2[] = {0x7F, 0x00, 0x00, 0x01}; /* Ip address: 127.0.0.1 */
        if ((san_ret = mbedtls_asn1_write_tagged_string(&san_ptr, san_buf,
                                                        (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_IP_ADDRESS),
                                                        san_ip2, sizeof(san_ip2))) <= 0) {
            goto out_mbedtls_mpi_free;
        } else {
            san_len += san_ret;
        }

        const char san_uri[] = "urn:unconfigured:application";
        if ((san_ret = mbedtls_asn1_write_tagged_string(&san_ptr, san_buf,
                                                        (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER),
                                                        san_uri, sizeof(san_uri))) <= 0) {
            goto out_mbedtls_mpi_free;
        } else {
            san_len += san_ret;
        }

        if ((san_ret = mbedtls_asn1_write_len(&san_ptr, san_buf, san_len)) <= 0) {
            goto out_mbedtls_mpi_free;
        } else {
            san_len += san_ret;
        }

        if ((san_ret = mbedtls_asn1_write_tag(&san_ptr, san_buf,
                                              (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))) <= 0) {
            goto out_mbedtls_mpi_free;
        } else {
            san_len += san_ret;
        }

        if ((err_num = mbedtls_x509write_crt_set_extension(&x509write_crt,
                                                           MBEDTLS_OID_SUBJECT_ALT_NAME,
                                                           MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                                                           0, san_ptr, san_len))) {
            PRINT_MBEDTLS_ERR(err_num);
            goto out_mbedtls_mpi_free;
        }
    }

    /* Generate CRT in DER encoding */
    if ((crt_buf_len = mbedtls_x509write_crt_der(&x509write_crt, crt_buf, sizeof(crt_buf),
                                                 mbedtls_ctr_drbg_random, &drbg_ctx)) <= 0) {
        PRINT_MBEDTLS_ERR(csr_buf_len);
        goto out_mbedtls_mpi_free;
    }

    /* Generate CRT in PEM encoding */
    if ((err_num = mbedtls_x509write_crt_pem(&x509write_crt, crt_buf, sizeof(crt_buf),
                                             mbedtls_ctr_drbg_random, &drbg_ctx))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_mbedtls_mpi_free;
    }

    PRINT("Generated a self-signed CRT in PEM encoding:\r\n");
    PRINT_HEADLESS("%s", crt_buf);
    PRINT_HEADLESS("\r\n");

    ret = 0;
out_mbedtls_mpi_free:
    mbedtls_mpi_free(&serial);
out_mbedtls_x509write_crt_free:
    mbedtls_x509write_crt_free(&x509write_crt);
    mbedtls_x509_csr_free(&x509_csr);
out_mbedtls_x509write_csr_free:
    mbedtls_x509write_csr_free(&x509write_csr);
    return ret;
}

int ecp(void)
{
    int i, err_num, ret = 1;

    ESYS_CONTEXT *esys_ctx;

    mbedtls_pk_context pk, pk_soft;
    mbedtls_tpm_ecp_context *tpm_ecp_ctx, *tpm_ecp_soft_ctx;

    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;
    unsigned char random[TPM2_SHA256_DIGEST_SIZE];

    size_t sig_len;
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];

    /* Initialize the ESYS_CONTEXT */

    if (tpm_open(&esys_ctx, TCTI_NAME_CONF)) {
        goto out;
    }

    /* Initialize mbedtls_pk_context */

    mbedtls_pk_init(&pk);
    mbedtls_pk_init(&pk_soft);

    if ((err_num = mbedtls_pk_setup(&pk, &tpm_ecp_info))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_release;
    }

    if ((err_num = mbedtls_pk_setup(&pk_soft, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_mbedtls_pk_free;
    }

    PRINT("Initialized mbedtls_pk_context.\n");

    /* Initialize mbedtls_tpm_ecp_context */

    tpm_ecp_ctx = (mbedtls_tpm_ecp_context *)pk.pk_ctx;
    tpm_ecp_soft_ctx = (mbedtls_tpm_ecp_context *)pk_soft.pk_ctx;

    if (tpm_ecp_init(tpm_ecp_ctx, esys_ctx)) {
        goto out_mbedtls_pk_soft_free;
    }

    if ((err_num = mbedtls_ecp_copy(&tpm_ecp_soft_ctx->ecp.Q, &tpm_ecp_ctx->ecp.Q))) { /* Copy the mbedtls_ecp_point */
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    if ((err_num = mbedtls_ecp_group_copy(&tpm_ecp_soft_ctx->ecp.grp, &tpm_ecp_ctx->ecp.grp))) { /* Copy the mbedtls_ecp_group */
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    PRINT("Initialized mbedtls_tpm_ecp_context.\n");

    /* Add an entropy source (TPM) to MbedTLS */

    if (tpm_entropy_init(&tpm_ecp_ctx->tpm, &drbg_ctx, &entropy_ctx)) {
        goto out_tpm_ecp_free;
    }

    PRINT("Added the TPM random generator as an entropy source for MbedTLS.\n");

    /* Verify the random generator */

    memset(random, 0, sizeof(random));
    if ((err_num = mbedtls_ctr_drbg_reseed(&drbg_ctx, NULL, 0))) { /* Reseeding (extracts data from entropy source) */
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }
    if ((err_num = mbedtls_ctr_drbg_random(&drbg_ctx, random, sizeof(random)))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    PRINT("Generated %"PRIuPTR"i bytes random: 0x", (uintptr_t)sizeof(random));
    for (i = 0; i < sizeof(random); i++) {
        PRINT_HEADLESS("%02X", random[i]);
    }
    PRINT_HEADLESS("\n");

    /* Check public-private key pair */

    if ((err_num = mbedtls_pk_check_pair(&pk, &pk))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    PRINT("The verification of the public-private key pair has passed.\n");

    /* Digital signing (TPM) and verification (TPM) */

    sig_len = 0;
    memset(sig, 0, sizeof(sig));
    if ((err_num = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
                                   random, sizeof(random), sig, &sig_len,
                                   mbedtls_ctr_drbg_random, &drbg_ctx))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    if ((err_num = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                                     random, sizeof(random), sig, sig_len))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    PRINT("Verification of digital signing (TPM) and verification (TPM) has passed.\n");

    /* Digital signing (TPM) and verification (soft) */

    sig_len = 0;
    memset(sig, 0, sizeof(sig));
    if ((err_num = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
                                   random, sizeof(random), sig, &sig_len,
                                   mbedtls_ctr_drbg_random, &drbg_ctx))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    if ((err_num = mbedtls_pk_verify(&pk_soft, MBEDTLS_MD_SHA256,
                                     random, sizeof(random), sig, sig_len))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_ecp_free;
    }

    PRINT("Verification of digital signing (TPM) and verification (soft) has passed.\n");

    if (x509_csr_crt(&pk, &drbg_ctx, &entropy_ctx)) {
        goto out_tpm_ecp_free;
    }

    ret = 0;
out_tpm_ecp_free:
    tpm_ecp_free(tpm_ecp_ctx);
out_mbedtls_pk_soft_free:
    mbedtls_pk_free(&pk_soft);
out_mbedtls_pk_free:
    mbedtls_pk_free(&pk);
out_tpm_release:
    tpm_release(&esys_ctx);
out:
    return ret;

}

int rsa(bool is_pkcs_v15)
{
    int i, err_num, ret = 1;

    ESYS_CONTEXT *esys_ctx;

    mbedtls_pk_context pk, pk_soft;
    mbedtls_tpm_rsa_context *tpm_rsa_ctx;
    const mbedtls_pk_info_t *pk_info;

    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;
    unsigned char random[32];

    size_t cipher_len, decipher_len;
    const unsigned char plain_text[] = "This is a plain text.";
    unsigned char cipher_text[512];
    unsigned char decipher_text[32];

    size_t sig_len;
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];

    /* Initialize the ESYS_CONTEXT */

    if (tpm_open(&esys_ctx, TCTI_NAME_CONF)) {
        goto out;
    }

    /* Initialize mbedtls_pk_context */

    mbedtls_pk_init(&pk);
    mbedtls_pk_init(&pk_soft);

    if (is_pkcs_v15) {
        pk_info = &tpm_rsa_pkcs_v15_info;
    } else {
        pk_info = &tpm_rsa_pkcs_v21_info;
    }

    if ((err_num = mbedtls_pk_setup(&pk, pk_info))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_release;
    }

    if ((err_num = mbedtls_pk_setup(&pk_soft, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_mbedtls_pk_free;
    }

    PRINT("Initialized mbedtls_pk_context.\n");

    /* Initialize mbedtls_tpm_rsa_context */

    tpm_rsa_ctx = (mbedtls_tpm_rsa_context *)pk.pk_ctx;

    if (tpm_rsa_init(tpm_rsa_ctx, is_pkcs_v15, esys_ctx)) {
        goto out_mbedtls_pk_soft_free;
    }

    if (mbedtls_rsa_copy((mbedtls_rsa_context *)pk_soft.pk_ctx, &tpm_rsa_ctx->rsa)) { /* Copy the rsa context */
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    PRINT("Initialized mbedtls_tpm_rsa_context.\n");

    /* Add an entropy source (TPM) to MbedTLS */

    if (tpm_entropy_init(&tpm_rsa_ctx->tpm, &drbg_ctx, &entropy_ctx)) {
        goto out_tpm_rsa_free;
    }

    PRINT("Added the TPM random generator as an entropy source for MbedTLS.\n");

    /* Verify the random generator */

    memset(random, 0, sizeof(random));
    if ((err_num = mbedtls_ctr_drbg_reseed(&drbg_ctx, NULL, 0))) { /* Reseeding (extracts data from entropy source) */
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }
    if ((err_num = mbedtls_ctr_drbg_random(&drbg_ctx, random, sizeof(random)))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    PRINT("Generated %"PRIuPTR"i bytes random: 0x", (uintptr_t)sizeof(random));
    for (i = 0; i < sizeof(random); i++) {
        PRINT_HEADLESS("%02X", random[i]);
    }
    PRINT_HEADLESS("\n");

    /* Check public-private key pair */

    if ((err_num = mbedtls_pk_check_pair(&pk, &pk))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    PRINT("The verification of the public-private key pair has passed.\n");

    /* Data encryption (TPM) and decryption (TPM) */

    cipher_len = 0;
    memset(cipher_text, 0, sizeof(cipher_text));
    if ((err_num = mbedtls_pk_encrypt(&pk, plain_text, sizeof(plain_text),
                                      cipher_text, &cipher_len, sizeof(cipher_text),
                                      NULL, NULL))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    decipher_len = 0;
    memset(decipher_text, 0, sizeof(decipher_text));
    if ((err_num = mbedtls_pk_decrypt(&pk, cipher_text, cipher_len,
                                      decipher_text, &decipher_len, sizeof(decipher_text),
                                      NULL, NULL))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    if (decipher_len != sizeof(plain_text) || memcmp(plain_text, decipher_text, decipher_len)) {
        PRINT("The deciphered text does not match the original plain text.");
        goto out_tpm_rsa_free;
    }

    PRINT("Verification of cipher (TPM) and decipher (TPM) operations has passed.\n");
    PRINT("Plain data used in the verification (%"PRIuPTR"-bytes): \"%s\"\n", (uintptr_t)sizeof(plain_text), plain_text);
    PRINT("Data in encrypted form (%"PRIuPTR"-bytes) is printed in hex: \"", (uintptr_t)cipher_len);
    for (i = 0; i < cipher_len; i++) {
        PRINT_HEADLESS("%02X", cipher_text[i]);
    }
    PRINT_HEADLESS("\"\n");
    PRINT("Data in decrypted form (%"PRIuPTR"-bytes): \"%s\"\n", (uintptr_t)decipher_len, decipher_text);

    /* Data encryption (soft) and decryption (TPM) */

    cipher_len = 0;
    memset(cipher_text, 0, sizeof(cipher_text));
    if ((err_num = mbedtls_pk_encrypt(&pk_soft, plain_text, sizeof(plain_text),
                                      cipher_text, &cipher_len, sizeof(cipher_text),
                                      mbedtls_ctr_drbg_random, &drbg_ctx))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    decipher_len = 0;
    memset(decipher_text, 0, sizeof(decipher_text));
    if ((err_num = mbedtls_pk_decrypt(&pk, cipher_text, cipher_len,
                                      decipher_text, &decipher_len, sizeof(decipher_text),
                                      NULL, NULL))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    if (decipher_len != sizeof(plain_text) || memcmp(plain_text, decipher_text, decipher_len)) {
        PRINT("The deciphered text does not match the original plain text.");
        goto out_tpm_rsa_free;
    }

    PRINT("Verification of cipher (soft) and decipher (TPM) operations has passed.\n");
    PRINT("Plain data used in the verification (%"PRIuPTR"-bytes): \"%s\"\n", (uintptr_t)sizeof(plain_text), plain_text);
    PRINT("Data in encrypted form (%"PRIuPTR"-bytes) is printed in hex: \"", (uintptr_t)cipher_len);
    for (i = 0; i < cipher_len; i++) {
        PRINT_HEADLESS("%02X", cipher_text[i]);
    }
    PRINT_HEADLESS("\"\n");
    PRINT("Data in decrypted form (%"PRIuPTR"-bytes): \"%s\"\n", (uintptr_t)decipher_len, decipher_text);

    /* Digital signing (TPM) and verification (TPM) */

    sig_len = 0;
    memset(sig, 0, sizeof(sig));
    if ((err_num = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
                                   random, sizeof(random), sig, &sig_len,
                                   mbedtls_ctr_drbg_random, &drbg_ctx))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    if ((err_num = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                                     random, sizeof(random), sig, sig_len))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    PRINT("Verification of digital signing (TPM) and verification (TPM) has passed.\n");

    /* Digital signing (TPM) and verification (soft) */

    sig_len = 0;
    memset(sig, 0, sizeof(sig));
    if ((err_num = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
                                   random, sizeof(random), sig, &sig_len,
                                   NULL, NULL))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    if ((err_num = mbedtls_pk_verify(&pk_soft, MBEDTLS_MD_SHA256,
                                     random, sizeof(random), sig, sig_len))) {
        PRINT_MBEDTLS_ERR(err_num);
        goto out_tpm_rsa_free;
    }

    PRINT("Verification of digital signing (TPM) and verification (soft) has passed.\n");

    /* The x509write_csr module does not support MBEDTLS_PK_RSASSA_PSS. */
    if (is_pkcs_v15) {
        if (x509_csr_crt(&pk, &drbg_ctx, &entropy_ctx)) {
            goto out_tpm_rsa_free;
        }
    }

    ret = 0;
out_tpm_rsa_free:
    tpm_rsa_free(tpm_rsa_ctx);
out_mbedtls_pk_soft_free:
    mbedtls_pk_free(&pk_soft);
out_mbedtls_pk_free:
    mbedtls_pk_free(&pk);
out_tpm_release:
    tpm_release(&esys_ctx);
out:
    return ret;
}

int mbedtls_examples()
{
    if (rsa(true)
        || rsa(true) /* Repeat to validate the provisioning detection. */
        || tpm_unprovision()
        || rsa(false)
        || tpm_unprovision()
        || ecp()
        || tpm_unprovision()
        ) {
        return 1;
    }

    return 0;
}
