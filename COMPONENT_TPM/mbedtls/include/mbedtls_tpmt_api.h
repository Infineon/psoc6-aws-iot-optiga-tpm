#ifndef MBEDTLS_TPMT_API_H_
#define MBEDTLS_TPMT_API_H_

#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

typedef struct {
    size_t length; /* The length of the string */
    uint8_t *data; /* The content (not null-terminated) */
} String;

mbedtls_rsa_context *mbedtls_tpmt_pk_rsa(mbedtls_pk_context *pk);

int mbedtls_tpmt_provision(void);
int mbedtls_tpmt_genSelfSignCrt(unsigned char *certificate, size_t *length);
int mbedtls_tpmt_genCsr(unsigned char *certificate, size_t *length);
int mbedtls_tpmt_pkctx_init(mbedtls_pk_context *pkctx);
int mbedtls_tpmt_pkctx_free(mbedtls_pk_context *pkctx);
int mbedtls_tpmt_random_init(mbedtls_ctr_drbg_context *drbgctx,
                                       mbedtls_entropy_context *entropyctx);
#endif
