#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/sha1.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1write.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls_tpmt_api.h"
#include "tpmt_api.h"

#define FILE_MBEDTLSTPMAPI "mbedtls_tpmt_api :"

#define ASN1_CHK_ADD(g,f)   do { \
                                    if( ( ret = f ) < 0 ) \
                                        return 1; \
                                    else \
                                        g += ret; \
                                } while( 0 )

mbedtls_rsa_context *mbedtls_tpmt_pk_rsa(mbedtls_pk_context *pk) {
    if (strcmp(mbedtls_pk_get_name(pk), "RSA-alt") == 0) {
        return (mbedtls_rsa_context *)((mbedtls_rsa_alt_context *)pk->pk_ctx)->key;
    } else {
        return NULL;
    }
}

static int mbedtls_tpmt_platfrom_entropy_poll(void *data, unsigned char *output,
                                     size_t len, size_t *olen) {
    uint16_t length = 0;

    printf("%s mbedtls_tpmt_platfrom_entropy_poll invoked\r\n", FILE_MBEDTLSTPMAPI);

    if (!len || (output == NULL) || ((void *)olen == NULL))
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    
    if (len > 65535)
        length = 65535;
    else
        length = (uint16_t)len;

    if (tpmt_fast_getRandom(output, &length)) {
        *olen = 0;
        return MBEDTLS_ERR_PK_HW_ACCEL_FAILED;
    }
    
    *olen = (size_t) length;
 
    return 0;
}

static int mbedtls_tpmt_rsa_decrypt_func( void *ctx, int mode, size_t *olen,
                       const unsigned char *input, unsigned char *output,
                       size_t output_max_len )
{
    uint16_t inlen = (uint16_t)((mbedtls_rsa_context *) ctx)->len;
    uint16_t outlen = (uint16_t)output_max_len;

    printf("%s mbedtls_tpmt_rsa_decrypt_func invoked\r\n", FILE_MBEDTLSTPMAPI);

    if (!inlen || !outlen || (output == NULL) || (input == NULL))
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        
    uint8_t *in = (uint8_t *)malloc(inlen);
    if (in == NULL)
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    memcpy(in, input, inlen);
    
    if (tpmt_fast_decipher(in, inlen, output, &outlen)) {
        printf("%s tpmt_fast_decipher error\r\n", FILE_MBEDTLSTPMAPI);
        free(in);
        *olen = 0;
        return MBEDTLS_ERR_PK_HW_ACCEL_FAILED;
    }
    free(in);
    *olen = outlen;

    return 0;
}

static int mbedtls_tpmt_rsa_sign_func( void *ctx,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                   int mode, mbedtls_md_type_t md_alg, unsigned int hashlen,
                   const unsigned char *hash, unsigned char *sig )
{
    ((void) f_rng);
    ((void) p_rng);
    uint16_t siglen = (uint16_t)((mbedtls_rsa_context *) ctx)->len;
    uint16_t length = 0;

    printf("%s mbedtls_tpmt_rsa_sign_func invoked\r\n", FILE_MBEDTLSTPMAPI);

    if (!hashlen || !siglen || (hash == NULL) || (sig == NULL))
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    
    if (hashlen > 65535)
        length = 65535;
    else
        length = (uint16_t)hashlen;

    uint8_t *in = (uint8_t *)malloc(length);
    if (in == NULL)
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    memcpy(in, hash, length);
    
    if (tpmt_fast_sign(in, length, sig, &siglen)) {
        printf("%s tpmt_fast_sign error\r\n", FILE_MBEDTLSTPMAPI);
        free(in);
        return MBEDTLS_ERR_PK_HW_ACCEL_FAILED;
    }

    free(in);

    return 0;
}

static size_t mbedtls_tpmt_rsa_key_len_func( void *ctx )
{
    return ((mbedtls_rsa_context *) ctx)->len;
}

int mbedtls_tpmt_provision(void) {
    if (tpmt_fast_perso()) {
        return 1;
    }
    return 0;
}

int mbedtls_tpmt_random_init(mbedtls_ctr_drbg_context *drbgctx,
                                       mbedtls_entropy_context *entropyctx) {

    mbedtls_ctr_drbg_init(drbgctx);
    mbedtls_entropy_init(entropyctx);
    int mbedErr = mbedtls_entropy_add_source(entropyctx,
                                         mbedtls_tpmt_platfrom_entropy_poll, NULL, 0,
                                         MBEDTLS_ENTROPY_SOURCE_STRONG);
    if(mbedErr != 0)
        return 1;
    
    char *personalization = "ifx-drbg";
    mbedErr = mbedtls_ctr_drbg_seed(drbgctx, mbedtls_entropy_func,
                                    entropyctx,
                                    (const unsigned char *)personalization, 14);
    if(mbedErr != 0)
        return 1;

    return 0;
}

int mbedtls_tpmt_pkctx_init(mbedtls_pk_context *pkctx) {

    /************************************
     ************************************
     * Create public key object, read from TPM
     * 
     */
    mbedtls_rsa_context *rsa_pk = (mbedtls_rsa_context *) malloc(sizeof(mbedtls_rsa_context));

    {
        uint32_t exponent;
        uint8_t mod[256];
        uint16_t modlen = sizeof(mod);

        if (tpmt_fast_getpk(&exponent, mod, &modlen)) {
            printf("%s tpmt_fast_getpk error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }

        mbedtls_rsa_init(rsa_pk, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
        rsa_pk->ver = 0;
        
        if ( mbedtls_mpi_read_binary(&rsa_pk->N, mod, modlen) != 0) {
            printf("%s mbedtls_mpi_read_binary error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
        
        if (exponent != 65537) {
            printf("%s bad rsa exponent\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }

        uint8_t exp[] = {0x1,0x0,0x1}; // exponent 0x65537
        if ( mbedtls_mpi_read_binary(&rsa_pk->E, exp, 3) != 0) {
            printf("%s mbedtls_mpi_read_binary error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }

        rsa_pk->len = mbedtls_mpi_bitlen(&rsa_pk->N) / 8;

        if ( mbedtls_rsa_check_pubkey(rsa_pk) != 0) {
            printf("%s mbedtls_rsa_check_pubkey error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
    }

    /************************************
     ************************************
     * Create bridge for TPM and mbedtls
     * 
     */
    mbedtls_pk_init( pkctx );

    {
        if (mbedtls_pk_setup_rsa_alt( pkctx, (void *) rsa_pk,
            mbedtls_tpmt_rsa_decrypt_func, mbedtls_tpmt_rsa_sign_func, mbedtls_tpmt_rsa_key_len_func ) != 0) {
            printf("%s mbedtls_pk_setup_rsa_alt error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
    }    

    return 0;
}

int mbedtls_tpmt_pkctx_free(mbedtls_pk_context *pkctx) {
    free((void *)mbedtls_tpmt_pk_rsa(pkctx));
    return 0;
}

int mbedtls_tpmt_genCsr(uint8_t *certificate, size_t *length) {

    printf("%s mbedtls_tpmt_genCsr invoked, TPM generates CSR (Certificate Sign Request)\r\n", FILE_MBEDTLSTPMAPI);

    if (*length < 4096 || certificate == NULL)
        return 1;

    /************************************
     ************************************
     * Use TPM as entropy provider
     * 
     */    
    mbedtls_ctr_drbg_context drbgctx;
    mbedtls_entropy_context entropyctx;
    if (mbedtls_tpmt_random_init(&drbgctx, &entropyctx) != 0)
        return 1;

    /************************************
     ************************************
     * Create public key object, read from TPM
     * Create bridge for TPM and mbedtls
     * 
     */
    mbedtls_pk_context alt;
    if (mbedtls_tpmt_pkctx_init(&alt) != 0) {
        return 1;
    }
    
    /************************************
     ************************************
     * Generate CSR
     * 
     */
    uint8_t csrbuf[4096];
    int32_t csrbuf_len;
    {

        mbedtls_x509write_csr csr;
        
        mbedtls_x509write_csr_init(&csr);
        mbedtls_x509write_csr_set_key(&csr, &alt);
        mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

        { // Set subject name
            const char *subject_name = "C=SG,ST=SG,L=8 Kallang Sector,O=Infineon Technologies,OU=Connected Secure Systems,CN=AWS IoT TPM Certificate";
            if (mbedtls_x509write_csr_set_subject_name( &csr, subject_name ) != 0) {
                printf("%s mbedtls_x509write_csr_set_subject_name error\r\n", FILE_MBEDTLSTPMAPI);
                return 1;
            }
        }

        if ((csrbuf_len = mbedtls_x509write_csr_pem(&csr, csrbuf, sizeof(csrbuf),
                                                    mbedtls_ctr_drbg_random, &drbgctx) ) < 0) {
            printf("%s mbedtls_x509write_csr error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }

        mbedtls_x509write_csr_free(&csr);

        printf("%s generated CSR encoded in PEM format\r\n", FILE_MBEDTLSTPMAPI);
        {
            printf("CSR PEM:\r\n");
            printf("%s",csrbuf);
            printf("\r\n");
        }

    }

    return 0;
}

int mbedtls_tpmt_genSelfSignCrt(uint8_t *certificate, size_t *length) {

    printf("%s mbedtls_tpmt_genSelfSignCrt invoked, TPM generates self-signed certificate\r\n", FILE_MBEDTLSTPMAPI);

    if (*length < 4096 || certificate == NULL)
        return 1;

    /************************************
     ************************************
     * Use TPM as entropy provider
     *
     */
    mbedtls_ctr_drbg_context drbgctx;
    mbedtls_entropy_context entropyctx;
    if (mbedtls_tpmt_random_init(&drbgctx, &entropyctx) != 0)
        return 1;

    /************************************
     ************************************
     * Create public key object, read from TPM
     * Create bridge for TPM and mbedtls
     *
     */
    mbedtls_pk_context alt;
    if (mbedtls_tpmt_pkctx_init(&alt) != 0) {
        return 1;
    }

    /************************************
     ************************************
     * Generate CSR
     *
     */
    uint8_t csrbuf[4096];
    int32_t csrbuf_len;
    {

        mbedtls_x509write_csr csr;

        mbedtls_x509write_csr_init(&csr);
        mbedtls_x509write_csr_set_key(&csr, &alt);
        mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

        { // Set subject name
            const char *subject_name = "C=SG,ST=SG,L=8 Kallang Sector,O=Infineon Technologies,OU=Connected Secure Systems,CN=AWS IoT TPM Certificate";
            if (mbedtls_x509write_csr_set_subject_name( &csr, subject_name ) != 0) {
                printf("%s mbedtls_x509write_csr_set_subject_name error\r\n", FILE_MBEDTLSTPMAPI);
                return 1;
            }
        }

        if ((csrbuf_len = mbedtls_x509write_csr_der(&csr, csrbuf, sizeof(csrbuf), 
                                                    mbedtls_ctr_drbg_random, &drbgctx) ) < 0) {
            printf("%s mbedtls_x509write_csr error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
        
        mbedtls_x509write_csr_free(&csr);

        /*printf("%s generated CSR encoded in DER format, CSR len=%d\r\n", FILE_MBEDTLSTPMAPI, csrbuf_len);
        {
            size_t i=0;
            printf("CSR DER:\r\n");
            for (;i<csrbuf_len;i++) printf("%02x",csrbuf[sizeof(csrbuf)-csrbuf_len+i]);
            printf("\r\n");
        }*/
    }

    /************************************
     ************************************
     * Generate self-sign CRT
     * 
     */
    uint8_t crtbuf[4096];
    {
        mbedtls_x509write_cert crt;
        mbedtls_x509_csr csr;
        int32_t rval;
        char subject_name[256];
        const char *issuer_name = "C=SG,O=IFX,CN=IFX_AP_DSS";
        
        mbedtls_x509write_crt_init(&crt);
        mbedtls_x509_csr_init(&csr);
        
        if ((rval = mbedtls_x509_csr_parse_der(&csr, csrbuf + sizeof(csrbuf) - csrbuf_len, (uint32_t)csrbuf_len)) < 0) {
            printf("%s mbedtls_x509_csr_parse_der error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
        
        if ((rval = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &csr.subject)) < 0) {
            printf("%s mbedtls_x509_dn_gets error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
        
        mbedtls_mpi serial;
        mbedtls_mpi_init(&serial);
        mbedtls_mpi_read_string(&serial, 10, "1");
        mbedtls_x509write_crt_set_serial(&crt, &serial);

        mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
        mbedtls_x509write_crt_set_subject_key(&crt, &csr.pk);
        mbedtls_x509write_crt_set_subject_key_identifier(&crt);
        
        mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name);
        mbedtls_x509write_crt_set_issuer_key(&crt, &alt);
        mbedtls_x509write_crt_set_authority_key_identifier(&crt);

        mbedtls_x509write_crt_set_validity(&crt, "20190102235959", "21001231235959");
        
        mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

        mbedtls_x509write_crt_set_key_usage( &crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE
                                                   | MBEDTLS_X509_KU_NON_REPUDIATION
                                                   | MBEDTLS_X509_KU_KEY_ENCIPHERMENT
                                                   | MBEDTLS_X509_KU_DATA_ENCIPHERMENT
                                                   | MBEDTLS_X509_KU_CRL_SIGN);
        
        mbedtls_x509write_crt_set_basic_constraints( &crt, 0, -1); // set FALSE if not CA, otherwise set TRUE

        { /* Set Subject Alternative Name */
#define X509V3_SUBALTNAME_DNS   2 // Subject Alternative Names (SANs)
#define X509V3_SUBALTNAME_IP    7 // Subject Alternative Names (SANs)
#define X509V3_SUBALTNAME_URI   6 // Subject Alternative Names (SANs)
            int	ret = 0;
            int len = 0;
            uint8_t *buf;
            uint8_t *pc;
            size_t buflen = 512;
            buf = (uint8_t *)calloc(1, buflen);
            memset(buf, 0, buflen);
            pc = buf + buflen;

            uint8_t dns1[] = "localhost";
            ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&pc, buf, (const unsigned char *)dns1, sizeof(dns1)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, sizeof(dns1)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | X509V3_SUBALTNAME_DNS));

            uint8_t dns2[] = "psoc6";
            ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&pc, buf, (const unsigned char *)dns2, sizeof(dns2)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, sizeof(dns2)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | X509V3_SUBALTNAME_DNS));

            uint8_t ip_all[] = {0x00, 0x00, 0x00, 0x00}; //0.0.0.0 all ip address
            ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&pc, buf, (const unsigned char *)ip_all, sizeof(ip_all)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, sizeof(ip_all)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | X509V3_SUBALTNAME_IP));

            uint8_t ip_localhost[] = {0x7F, 0x00, 0x00, 0x01}; //127.0.0.1 localhost
            ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&pc, buf, (const unsigned char *)ip_localhost, sizeof(ip_localhost)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, sizeof(ip_localhost)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | X509V3_SUBALTNAME_IP));

            uint8_t uri[] = "urn:unconfigured:application";
            ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&pc, buf, (const unsigned char *)uri, sizeof(uri)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, sizeof(uri)));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | X509V3_SUBALTNAME_URI));
            
            // Wrap all alt subjects together
            ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, (size_t)len));
            ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

            ret = mbedtls_x509write_crt_set_extension( &crt,
                                                       MBEDTLS_OID_SUBJECT_ALT_NAME,
                                                       MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                                                       0,
                                                       buf + buflen - len,
                                                       (size_t)len);
            free(buf);
        }

        if ((rval = mbedtls_x509write_crt_der(&crt, crtbuf, *length,
                                                 mbedtls_ctr_drbg_random, &drbgctx)) <= 0) {
            printf("%s mbedtls_x509write_crt_der error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
        *length = (size_t)rval;
        memcpy(certificate, crtbuf + sizeof(crtbuf)-rval, (size_t)rval);

        /*printf("generated CRT encoded in DER format, CRT len=%d \n", *length);
        {
            size_t i=0;
            printf("CRT DER:\n");
            for (;i<(size_t)rval;i++) printf("%02x",certificate[i]);
            printf("\n");
        }*/

        if (mbedtls_x509write_crt_pem(&crt, crtbuf, sizeof(crtbuf), mbedtls_ctr_drbg_random, &drbgctx) < 0) {
            printf("%s mbedtls_x509write_crt_pem error\r\n", FILE_MBEDTLSTPMAPI);
            return 1;
        }
        
        mbedtls_x509write_crt_free(&crt);
        mbedtls_x509_csr_free(&csr);

        printf("%s generated CRT encoded in PEM format\r\n", FILE_MBEDTLSTPMAPI);
        {
            printf("CRT PEM:\r\n");
            printf("%s",crtbuf);
            printf("\r\n");
        }

    }

    return 0;
}

