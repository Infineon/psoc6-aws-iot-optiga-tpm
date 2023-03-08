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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "tss2_util.h"
#ifndef TCTILDR_ENABLE
#include "tcti_spi_psoc6.h"
#endif

static int tss2_openEncryptedSession(ESYS_CONTEXT *esys_ctx,
                                     TPM2_HANDLE ses_key_handle,
                                     const char *ses_key_auth,
                                     TPM2_HANDLE *ses_handle)
{
    TPM2B_DIGEST        pwd;
    ESYS_TR             key_object;
    TSS2_RC             rval;
    TPMT_SYM_DEF        sym = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {
            .aes = TSS2_DEFAULT_AES_KEY_BITS
        },
        .mode = {
            .aes = TPM2_ALG_CFB
        }
    };

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", ses_key_auth);

    rval = Esys_TR_FromTPMPublic(esys_ctx, ses_key_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
               rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_StartAuthSession(esys_ctx, key_object, key_object, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &sym,
                                 TSS2_DEFAULT_SES_AUTH_ALG, ses_handle);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        PRINT("Esys_StartAuthSession has failed with error code: 0x%" PRIX32 "(%s).\n",
               rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_TRSess_SetAttributes(esys_ctx, *ses_handle,
                                     TPMA_SESSION_CONTINUESESSION |
                                     TPMA_SESSION_DECRYPT |
                                     TPMA_SESSION_ENCRYPT, 0xff);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TRSess_SetAttributes has failed with error code: 0x%" PRIX32 "(%s).\n",
               rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Opened encrypted session.\n");
    return 0;
}

static int tss2_closeEncryptedSession(ESYS_CONTEXT *esys_ctx,
                                      TPM2_HANDLE ses_handle)
{
    TSS2_RC rval;

    rval = Esys_FlushContext(esys_ctx, ses_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_FlushContext has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Closed encrypted session.\n");
    return 0;
}

static int tss2_alg2HashSize(TPM2_ALG_ID id)
{
    switch (id) {
        case TPM2_ALG_SHA1:
            return TPM2_SHA1_DIGEST_SIZE;
        case TPM2_ALG_SHA256:
            return TPM2_SHA256_DIGEST_SIZE;
        case TPM2_ALG_SHA384:
            return TPM2_SHA384_DIGEST_SIZE;
        case TPM2_ALG_SHA512:
            return TPM2_SHA512_DIGEST_SIZE;
        case TPM2_ALG_SM3_256:
            return TPM2_SM3_256_DIGEST_SIZE;
    }

    return 0;
}

int tss2_clearPersistentHandle(ESYS_CONTEXT *esys_ctx,
                               TPM2_HANDLE p_handle,
                               const char *sh_auth)
{
    TPM2B_DIGEST pwd;
    TSS2_RC      rval;
    ESYS_TR      handle, dummy;

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", sh_auth);

    rval = Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_TR_FromTPMPublic(esys_ctx, p_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
               rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             ESYS_TR_NONE, &dummy);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_EvictControl has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Cleared persistent handle: 0x%" PRIX32 ".\n", p_handle);
    return 0;
}

int tss2_clearTransientHandle(ESYS_CONTEXT *esys_ctx,
                              TPM2_HANDLE t_handle)
{
    ESYS_TR handle;
    TPM2_RC rval;

    rval = Esys_TR_FromTPMPublic(esys_ctx, t_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_FlushContext(esys_ctx, handle);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_FlushContext has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Cleared transient handle: 0x%" PRIX32 ".\n", t_handle);
    return 0;
}

int tss2_close(ESYS_CONTEXT **esys_ctx)
{
    int                 ret = 1;
    TSS2_TCTI_CONTEXT   *tcti = NULL;
    TSS2_RC             rval;

    rval = Esys_GetTcti(*esys_ctx, &tcti);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_GetTcti has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out;
    }

    Esys_Finalize(esys_ctx);

#ifdef TCTILDR_ENABLE
    Tss2_TctiLdr_Finalize(&tcti);
#else
    Tss2_Tcti_Finalize(tcti);
    free(tcti);
#endif

    ret = 0;
out:
    return ret;
}

int tss2_createEcpKey(ESYS_CONTEXT *esys_ctx,
                      TPM2_HANDLE parent_key_handle,
                      const char *parent_key_auth,
                      TPM2_HANDLE key_handle,
                      const char *key_auth)
{
    int                     ret = 1;
    TPM2B_PUBLIC            *out_public;
    TPM2B_PRIVATE           *out_private;
    ESYS_TR                 persistent_handle, transient_handle, key_object;
    TPM2_RC                 rval;
    TPM2B_DIGEST pwd;
    TPM2B_CREATION_DATA     *creation_data = NULL;
    TPM2B_DIGEST            *creation_hash = NULL;
    TPMT_TK_CREATION        *creation_ticket = NULL;
    TPM2B_SENSITIVE_CREATE  in_sensitive_leaf = {0};
    TPM2B_DATA              outsideInfo = {0};
    TPML_PCR_SELECTION      creation_pcr = {0};
    TPM2B_PUBLIC            in_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TSS2_DEFAULT_NAME_ALG,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                 TPMA_OBJECT_SIGN_ENCRYPT),
            .authPolicy = {
                .size = 0,
            },
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {{0}}
                },
                .curveID = TSS2_DEFAULT_EC_CURVE,
                .kdf = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {{0}}
                }
            },
            .unique.ecc = {
                .x = { .size = 0, .buffer = {0} },
                .y = { .size = 0, .buffer = {0} }
            }
        },
    };

    /* 1) Create key */
    {
        rval = Esys_TR_FromTPMPublic(esys_ctx, parent_key_handle, ESYS_TR_NONE,
                                     ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
        if (rval != TSS2_RC_SUCCESS) {
            PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", parent_key_auth);

        rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", key_auth);
        in_sensitive_leaf.sensitive.userAuth = pwd;

        rval = Esys_Create(esys_ctx, key_object,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &in_sensitive_leaf, &in_public, &outsideInfo, &creation_pcr,
                           &out_private, &out_public, &creation_data, &creation_hash,
                           &creation_ticket);

        free(creation_data);
        free(creation_hash);
        free(creation_ticket);

        if(rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_Create has failed with error code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out;
        }
    }

    /* 2) Make key persistent */
    {
        rval = Esys_TR_FromTPMPublic(esys_ctx, parent_key_handle, ESYS_TR_NONE,
                                     ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
        if (rval != TSS2_RC_SUCCESS) {
            PRINT("Esys_TR_FromTPMPublic has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out_free_pub_priv;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", parent_key_auth);

        rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_TR_SetAuth has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out_free_pub_priv;
        }

        rval = Esys_Load(esys_ctx, key_object,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         out_private, out_public, &transient_handle);
        if (rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_Load has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out_free_pub_priv;
        }
    }

    rval = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, transient_handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                     key_handle, &persistent_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_EvictControl has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_free_pub_priv;
    }

    rval = Esys_FlushContext(esys_ctx, transient_handle);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_FlushContext has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_free_pub_priv;
    }

    PRINT("Created an EC key and persisted it at the handle 0x%" PRIX32 ".\n",
          key_handle);

    ret = 0;
out_free_pub_priv:
    free(out_public);
    free(out_private);
out:
    return ret;
}

int tss2_createPrimaryKey(ESYS_CONTEXT *esys_ctx,
                          TPM2_HANDLE key_handle,
                          const char *sh_auth,
                          const char *srk_auth)
{
    TPM2B_DIGEST            pwd;
    TSS2_RC                 rval;
    ESYS_TR                 persistent_handle = ESYS_TR_NONE;
    ESYS_TR                 transient_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC            *out_public = NULL;
    TPM2B_CREATION_DATA     *creation_data = NULL;
    TPM2B_DIGEST            *creation_hash = NULL;
    TPMT_TK_CREATION        *creation_ticket = NULL;
    TPM2B_SENSITIVE_CREATE  in_sensitive_primary = {0};
    TPM2B_DATA              outsideInfo = {0};
    TPML_PCR_SELECTION      creation_pcr = {0};
    TPM2B_PUBLIC            in_public = {
        /* This is equivalent to "tpm2_createprimary -a o -P owner123 -p RSAprimary123 -g 0x000B -G 0x0001 -o RSAprimary.ctx" */
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TSS2_DEFAULT_NAME_ALG,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_RESTRICTED),
            .authPolicy = {
                 .size = 0,
            },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = TSS2_DEFAULT_AES_KEY_BITS,
                     .mode.aes = TPM2_ALG_CFB
                 },
                 .scheme = {
                     .scheme = TPM2_ALG_NULL
                 },
                 .keyBits = TSS2_DEFAULT_RSA_KEY_BITS,
                 .exponent = 0,
            },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {0},
            },
        },
    };

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", sh_auth);
    rval = Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", srk_auth);
    in_sensitive_primary.sensitive.userAuth = pwd;

    rval = Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                              ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive_primary,
                              &in_public, &outsideInfo, &creation_pcr,
                              &transient_handle, &out_public, &creation_data,
                              &creation_hash, &creation_ticket);

    free(out_public);
    free(creation_data);
    free(creation_hash);
    free(creation_ticket);

    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_CreatePrimary has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, transient_handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             key_handle, &persistent_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_EvictControl has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_FlushContext(esys_ctx, transient_handle);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_FlushContext has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Created an RSA primary key and persisted it at the handle 0x%" PRIX32 ".\n",
          key_handle);

    return 0;
}

int tss2_createRsaKey(ESYS_CONTEXT *esys_ctx,
                      TPM2_HANDLE parent_key_handle,
                      const char *parent_key_auth,
                      TPM2_HANDLE key_handle,
                      const char *key_auth)
{
    int                     ret = 1;
    ESYS_TR                 transient_handle;
    ESYS_TR                 persistent_handle;
    ESYS_TR                 key_object;
    TPM2B_PUBLIC            *out_public;
    TPM2B_PRIVATE           *out_private;
    TPM2_RC                 rval;
    TPM2B_DIGEST            pwd;
    TPM2B_DATA              outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION      creation_pcr = { .count = 0 };
    TPM2B_CREATION_DATA     *creation_data = NULL;
    TPM2B_DIGEST            *creation_hash = NULL;
    TPMT_TK_CREATION        *creation_ticket = NULL;
    TPM2B_SENSITIVE_CREATE  in_sensitive_leaf = {0};
    TPM2B_PUBLIC            in_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TSS2_DEFAULT_NAME_ALG,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                 TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL,
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                },
                .keyBits = TSS2_DEFAULT_RSA_KEY_BITS,
                .exponent = 0,
             },
            .unique.rsa = {
                .size = 0,
                .buffer = {0},
            },
        },
    };

    /* 1) Create key */
    {
        rval = Esys_TR_FromTPMPublic(esys_ctx, parent_key_handle, ESYS_TR_NONE,
                                     ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
        if (rval != TSS2_RC_SUCCESS) {
            PRINT("Esys_TR_FromTPMPublic error.\n");
            goto out;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", parent_key_auth);

        rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_TR_SetAuth error.\n");
            goto out;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", key_auth);
        in_sensitive_leaf.sensitive.userAuth = pwd;


        rval = Esys_Create(esys_ctx, key_object,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &in_sensitive_leaf, &in_public, &outsideInfo, &creation_pcr,
                           &out_private, &out_public, &creation_data, &creation_hash,
                           &creation_ticket);

        free(creation_data);
        free(creation_hash);
        free(creation_ticket);

        if (rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_Create has failed with error code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out;
        }
    }

    /* 2) Load key */

    {
        rval = Esys_TR_FromTPMPublic(esys_ctx, parent_key_handle, ESYS_TR_NONE,
                                     ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
        if (rval != TSS2_RC_SUCCESS) {
            PRINT("Esys_TR_FromTPMPublic has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out_free_pub_priv;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", parent_key_auth);
        rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_TR_SetAuth has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out_free_pub_priv;
        }

        rval = Esys_Load(esys_ctx, key_object,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         out_private, out_public, &transient_handle);
        if (rval != TPM2_RC_SUCCESS) {
            PRINT("Esys_Load has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
                  rval, Tss2_RC_Decode(rval));
            goto out_free_pub_priv;
        }
    }

    rval = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, transient_handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             key_handle, &persistent_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_EvictControl has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_free_pub_priv;
    }

    rval = Esys_FlushContext(esys_ctx, transient_handle);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_FlushContext has failed with out_free_pub_privor code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_free_pub_priv;
    }

    PRINT("Created an RSA key and persisted it at the handle 0x%" PRIX32 ".\n",
          key_handle);

    ret = 0;
out_free_pub_priv:
    free(out_public);
    free(out_private);
out:
    return ret;
}

int tss2_cipher(ESYS_CONTEXT *esys_ctx,
                TPM2_HANDLE key_handle,
                TPM2_HANDLE ses_key_handle,
                const char *ses_key_auth,
                TPM2_ALG_ID padding_scheme,
                TPM2_ALG_ID hash_algo,
                const BYTE *data_in,
                UINT16 in_len,
                BYTE *data_out,
                UINT16 *out_len)
{
    int                     ret = 1;
    TPM2_RC                 rval;
    ESYS_TR                 key_object;
    TPMT_RSA_DECRYPT        scheme = {0};
    TPM2_HANDLE             ses_handle;
    TPM2B_PUBLIC_KEY_RSA    *encrypted_msg = NULL;
    TPM2B_DATA label = {0};
    TPM2B_PUBLIC_KEY_RSA    clear_msg = {
        .size = in_len,
    };

    switch (padding_scheme) {
        case TPM2_ALG_OAEP:
            scheme.scheme = TPM2_ALG_OAEP;
            scheme.details.oaep.hashAlg = hash_algo;
            break;
        case TPM2_ALG_RSAES:
            scheme.scheme = TPM2_ALG_RSAES;
            break;
        default:
            PRINT("unknown padding scheme.\n");
            goto out;
    }

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    memcpy(clear_msg.buffer, data_in, in_len);

    rval = Esys_TR_FromTPMPublic(esys_ctx, key_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    rval = Esys_RSA_Encrypt(esys_ctx, key_object,
                            ses_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                            &clear_msg, &scheme, &label, &encrypted_msg);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_RSA_Encrypt has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    if (encrypted_msg->size > *out_len) {
        PRINT("Insufficient output buffer size.\n");
        goto out_free_encrypted_msg;
    }

    memcpy(data_out, encrypted_msg->buffer, encrypted_msg->size);
    *out_len = encrypted_msg->size;

    PRINT("Encrypted using RSA key from handle 0x%" PRIX32 ".\n", key_handle);

    ret = 0;
out_free_encrypted_msg:
    free(encrypted_msg);
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_decipher(ESYS_CONTEXT *esys_ctx,
                  TPM2_HANDLE key_handle,
                  const char *key_auth,
                  TPM2_HANDLE ses_key_handle,
                  const char *ses_key_auth,
                  TPM2_ALG_ID padding_scheme,
                  TPM2_ALG_ID hash_algo,
                  const BYTE *data_in,
                  UINT16 in_len,
                  BYTE *data_out,
                  UINT16 *out_len)
{
    int                     ret = 1;
    TPM2_RC                 rval;
    TPM2B_DATA              null_data = {0};
    TPMT_RSA_DECRYPT        scheme = {0};
    TPM2_HANDLE             ses_handle;
    ESYS_TR                 key_object;
    TPM2B_DIGEST            pwd;
    TPM2B_PUBLIC_KEY_RSA    *decrypted_msg = NULL;
    TPM2B_PUBLIC_KEY_RSA    encrypted_msg = {
        .size = in_len,
    };

    if (in_len % TSS2_DEFAULT_RSA_KEY_BYTES) {
        PRINT("The provided input data length is not supported.\n");
        goto out;
    }

    switch (padding_scheme) {
        case TPM2_ALG_OAEP:
            scheme.scheme = TPM2_ALG_OAEP;
            scheme.details.oaep.hashAlg = hash_algo;
            break;
        case TPM2_ALG_RSAES:
            scheme.scheme = TPM2_ALG_RSAES;
            break;
        default:
            PRINT("Unknown padding scheme.\n");
            goto out;
    }

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    memcpy(encrypted_msg.buffer, data_in, in_len);

    rval = Esys_TR_FromTPMPublic(esys_ctx, key_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", key_auth);

    rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    rval = Esys_RSA_Decrypt(esys_ctx, key_object, ses_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                            &encrypted_msg, &scheme, &null_data, &decrypted_msg);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_RSA_Decrypt has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    if (decrypted_msg->size > *out_len) {
        PRINT("Insufficient output buffer size.\n");
        goto out_free_decrypted_msg;
    }

    memcpy(data_out, decrypted_msg->buffer, decrypted_msg->size);
    *out_len = decrypted_msg->size;

    PRINT("Decrypted using RSA key from handle 0x%" PRIX32 ".\n", key_handle);

    ret = 0;
out_free_decrypted_msg:
    free(decrypted_msg);
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_ecpSign(ESYS_CONTEXT *esys_ctx,
                 TPM2_HANDLE key_handle,
                 const char *key_auth,
                 TPM2_HANDLE ses_key_handle,
                 const char *ses_key_auth,
                 TPM2_ALG_ID sig_scheme,
                 TPM2_ALG_ID hash_algo,
                 const BYTE *data_in,
                 UINT16 in_len,
                 BYTE *sig_r,
                 UINT16 *r_len,
                 BYTE *sig_s,
                 UINT16 *s_len)
{
    int ret = 1;
    TPM2_RC rval;
    TPMT_SIG_SCHEME scheme = {0};
    TPM2_HANDLE ses_handle;
    ESYS_TR key_object;
    TPM2B_DIGEST pwd;
    TPM2B_DIGEST digest = {
        .size = in_len
    };
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {0}
    };
    TPMT_SIGNATURE *signature = NULL;

    if (in_len != tss2_alg2HashSize(hash_algo)) {
        PRINT("Invalid data size.\n");
        goto out;
    }

    switch (sig_scheme) {
        case TPM2_ALG_ECDSA:
            scheme.scheme = TPM2_ALG_ECDSA;
            scheme.details.ecdsa.hashAlg = hash_algo;
            break;
        default:
            PRINT("Unknown signature scheme.\n");
            goto out;
    }

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    memcpy(digest.buffer, data_in, in_len);

    rval = Esys_TR_FromTPMPublic(esys_ctx, key_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", key_auth);
    rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    rval = Esys_Sign(esys_ctx, key_object,
                     ses_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                     &digest, &scheme, &hash_validation, &signature);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_Sign has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    switch (sig_scheme) {
        case TPM2_ALG_ECDSA:
            if (*s_len < signature->signature.ecdsa.signatureS.size ||
                *r_len < signature->signature.ecdsa.signatureR.size) {
                PRINT("Insufficient output buffer size.");
                goto out_free_signature;
            }
            *s_len = signature->signature.ecdsa.signatureS.size;
            memcpy(sig_s, signature->signature.ecdsa.signatureS.buffer, *s_len);
            *r_len = signature->signature.ecdsa.signatureR.size;
            memcpy(sig_r, signature->signature.ecdsa.signatureR.buffer, *r_len);
            break;
    }

    PRINT("Signed using EC key from handle 0x%" PRIX32 ".\n", key_handle);

    ret = 0;
out_free_signature:
    free(signature);
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_ecpVerify(ESYS_CONTEXT *esys_ctx,
                   TPM2_HANDLE key_handle,
                   TPM2_HANDLE ses_key_handle,
                   const char *ses_key_auth,
                   TPM2_ALG_ID scheme,
                   TPM2_ALG_ID hash_algo,
                   const BYTE *data_in,
                   UINT16 in_len,
                   BYTE *sig_r,
                   UINT16 r_len,
                   BYTE *sig_s,
                   UINT16 s_len,
                   int *result)
{
    int                 ret = 1, mask;
    ESYS_TR             key_object;
    TPM2_RC             rval;
    TPMT_SIGNATURE      signature = {0};
    TPM2_HANDLE         ses_handle;
    TPMT_TK_VERIFIED    *validation = NULL;
    TPM2B_DIGEST        hash = {
        .size = in_len
    };

    if (in_len != tss2_alg2HashSize(hash_algo) ||
        r_len > TPM2_MAX_ECC_KEY_BYTES ||
        s_len > TPM2_MAX_ECC_KEY_BYTES ) {
        PRINT("tss2_ecpVerify unsupported data buffer size.\n");
        goto out;
    }

    *result = 0;

    switch (scheme) {
        case TPM2_ALG_ECDSA:
            signature.sigAlg = TPM2_ALG_ECDSA;
            signature.signature.ecdsa.hash = hash_algo;
            signature.signature.ecdsa.signatureR.size = r_len;
            memcpy(signature.signature.ecdsa.signatureR.buffer, sig_r, r_len);
            signature.signature.ecdsa.signatureS.size = s_len;
            memcpy(signature.signature.ecdsa.signatureS.buffer, sig_s, s_len);
            break;
        default:
            PRINT("unknown signature scheme.\n");
            goto out;
    }

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    memcpy(hash.buffer, data_in, in_len);

    rval = Esys_TR_FromTPMPublic(esys_ctx, key_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    rval = Esys_VerifySignature(esys_ctx, key_object,
                                ses_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                                &hash, &signature, &validation);
    mask = rval & TPM2_RC_SIGNATURE;
    if (rval != TSS2_RC_SUCCESS && !mask) {
        PRINT("Esys_VerifySignature has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    if (rval == TSS2_RC_SUCCESS) {
        *result = 1;
    }

    PRINT("Signature verified using EC key from handle 0x%" PRIX32 ".\n", key_handle);

    free(validation);

    ret = 0;
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_forceClear(ESYS_CONTEXT *esys_ctx)
{
    TSS2_RC rval;

    rval = Esys_Clear(esys_ctx, ESYS_TR_RH_PLATFORM,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_Clear has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("TPM force cleared.\n");
    return 0;
}

int tss2_getRandom(ESYS_CONTEXT *esys_ctx,
                   TPM2_HANDLE ses_key_handle,
                   const char *ses_key_auth,
                   BYTE *rnd,
                   UINT16 *len)
{
    int             ret = 1;
    TPM2_HANDLE     ses_handle = ESYS_TR_NONE;
    TPM2B_DIGEST    *random_bytes = NULL;
    TSS2_RC         rval;

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    rval = Esys_GetRandom(esys_ctx, ses_handle,
                          ESYS_TR_NONE, ESYS_TR_NONE,
                          *len, &random_bytes);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_GetRandom has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    *len = random_bytes->size;
    memcpy(rnd, random_bytes->buffer, *len);

    free(random_bytes);

    PRINT("Executed get random.\n");

    ret = 0;
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_getSysHandle(ESYS_CONTEXT *esys_ctx,
                      UINT32 property,
                      int *count,
                      TPM2_HANDLE **sys_handles)
{
    int                     ret = 1;
    UINT16                  i = 0;
    TPMI_YES_NO             more_data;
    TPMS_CAPABILITY_DATA    *fetched_data = NULL;
    TSS2_RC                 rval;

    rval = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, TPM2_CAP_HANDLES, property,
                              TPM2_MAX_CAP_HANDLES, &more_data, &fetched_data);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_GetCapability has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out;
    }

    *count = fetched_data->data.handles.count;

    if (*count > 0) {
        PRINT("found %d handles:\n", *count);

        if (sys_handles) {
            *sys_handles = calloc(1, sizeof(TPM2_HANDLE)*(*count));
            if (!sys_handles) {
                PRINT("calloc has failed.\n");
                goto out_free_fetched_data;
            }
        }

        for (; i < *count; i++) {
            PRINT_HEADLESS("- 0x%" PRIX32 "\n", fetched_data->data.handles.handle[i]);
            if (sys_handles) {
                *((*sys_handles) + i) = fetched_data->data.handles.handle[i];
            }
        }
    }

    ret = 0;
out_free_fetched_data:
    Esys_Free(fetched_data);
out:
    return ret;
}

int tss2_nvCompare(ESYS_CONTEXT *esys_ctx,
                   TPM2_HANDLE nv_index,
                   const BYTE *magic,
                   UINT16 magic_len,
                   bool *is_equal)
{
    int         ret = 1;
    int         sys_handle_count;
    TPM2_HANDLE *sys_handles;
    UINT16      nv_len;
    BYTE        *nv;

    *is_equal = false;

    nv_len = magic_len;
    nv = calloc(1, magic_len);
    if (!nv) {
        goto out;
    }

    if (tss2_getSysHandle(esys_ctx, TPM2_NV_INDEX_FIRST, &sys_handle_count, &sys_handles)) {
        goto out_free_nv;
    }

    while (sys_handle_count--) {
        if (sys_handles[sys_handle_count] == nv_index) {
            if (tss2_nvRead(esys_ctx, nv_index, nv, &nv_len)) {
                goto out_free_sys_handles;
            }

            if (nv_len == magic_len &&
                !memcmp(nv, magic, magic_len)) {
                *is_equal = true;
            }

            break;
        }
    }

    ret = 0;
out_free_sys_handles:
    free(sys_handles);
out_free_nv:
    free(nv);
out:
    return ret;
}

int tss2_nvDefine(ESYS_CONTEXT *esys_ctx,
                  TPM2_HANDLE nv_index,
                  UINT16 len)
{
    TPM2_RC         rval;
    ESYS_TR         nvHandle = ESYS_TR_NONE;
    TPM2B_AUTH      auth = {0};
    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = nv_index,
            .nameAlg = TSS2_DEFAULT_NAME_ALG,
            .attributes = (
                TPMA_NV_PLATFORMCREATE |
                TPMA_NV_PPWRITE |
                TPMA_NV_PPREAD |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_AUTHREAD
            ),
            .authPolicy = {
                .size = 0,
            },
            .dataSize = len,
        }
    };

    rval = Esys_NV_DefineSpace(esys_ctx, ESYS_TR_RH_PLATFORM, ESYS_TR_PASSWORD,
                               ESYS_TR_NONE, ESYS_TR_NONE, &auth,
                               &publicInfo, &nvHandle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_NV_DefineSpace has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("NV defined at 0x%" PRIX32 ".\n", nv_index);

    return 0;
}

int tss2_nvUndefine(ESYS_CONTEXT *esys_ctx,
                    TPM2_HANDLE nv_index)
{
    TPM2_RC rval;
    ESYS_TR esys_nv_index;

    rval = Esys_TR_FromTPMPublic(esys_ctx, nv_index, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &esys_nv_index);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_NV_UndefineSpace(esys_ctx, ESYS_TR_RH_PLATFORM, esys_nv_index,
                                 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_NV_UndefineSpace has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("NV at 0x%" PRIX32 " has been undefined.\n", nv_index);

    return 0;
}

int tss2_nvRead(ESYS_CONTEXT *esys_ctx,
                TPM2_HANDLE nv_index,
                BYTE *data,
                UINT16 *len)
{
    TPM2_RC             rval;
    ESYS_TR             esys_nv_index;
    TPM2B_MAX_NV_BUFFER *nvData = NULL;
    UINT16              size = *len;
    UINT16              offset = 0;

    rval = Esys_TR_FromTPMPublic(esys_ctx, nv_index, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &esys_nv_index);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_NV_Read(esys_ctx,
                        esys_nv_index,
                        esys_nv_index, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                        ESYS_TR_NONE, size, offset, &nvData);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_NV_Read has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    memcpy(data, nvData->buffer, nvData->size);
    *len = nvData->size;

    PRINT("Read %d bytes from NV index 0x%" PRIX32 ": 0x", *len, nv_index);
    for (offset = 0; offset < nvData->size; offset++) {
        PRINT_HEADLESS("%02x", nvData->buffer[offset]);
    }
    PRINT_HEADLESS("\n");

    free(nvData);

    return 0;
}

int tss2_nvWrite(ESYS_CONTEXT *esys_ctx,
                 TPM2_HANDLE nv_index,
                 const BYTE *data,
                 UINT16 len)
{
    TPM2_RC             rval;
    ESYS_TR             esys_nv_index;
    UINT16              offset = 0;
    TPM2B_MAX_NV_BUFFER nvData;

    rval = Esys_TR_FromTPMPublic(esys_ctx, nv_index, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &esys_nv_index);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    nvData.size = len;
    memcpy(nvData.buffer, data, len);

    rval = Esys_NV_Write(esys_ctx,
                         esys_nv_index,
                         esys_nv_index, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                         ESYS_TR_NONE, &nvData, offset);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_NV_Write has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Write %d bytes to NV index 0x%" PRIX32 ": 0x", len, nv_index);
    for (offset = 0; offset < nvData.size; offset++) {
        PRINT_HEADLESS("%02x", nvData.buffer[offset]);
    }
    PRINT_HEADLESS("\n");

    return 0;
}

int tss2_open(ESYS_CONTEXT **esys_ctx,
              const char *tcti_name_conf)
{
    int                 ret = 1;
    TSS2_TCTI_CONTEXT   *tcti;
#ifndef TCTILDR_ENABLE
    size_t              size;
#endif
    TSS2_RC             rc;

    /* Get the TCTI context */
#ifdef TCTILDR_ENABLE
    rc = Tss2_TctiLdr_Initialize(tcti_name_conf, &tcti);
#else
    rc = Tss2_Tcti_Spi_Psoc6_Init(NULL, &size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        PRINT("Failed to get the size of a tcti context.\n");
        goto out;
    }

    tcti = calloc(1, size);
    if (!tcti) {
        PRINT("calloc has failed.\n");
        goto out;
    }

    rc = Tss2_Tcti_Spi_Psoc6_Init(tcti, &size, NULL);
#endif
    if (rc != TSS2_RC_SUCCESS) {
        PRINT("Failed to initialize the tcti context.\n");
#ifdef TCTILDR_ENABLE
        goto out;
#else
        goto out_free_tcti;
#endif
    }


    /* Initializing the Esys context */
    rc = Esys_Initialize(esys_ctx, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        PRINT("Failed to initialize the Esys context.\n");
#ifndef TCTILDR_ENABLE
        goto out_free_tcti;
#endif
    }

    ret = 0;
    goto out;
#ifndef TCTILDR_ENABLE
out_free_tcti:
    free(tcti);
#endif
out:
    return ret;
}

int tss2_persistHandle(ESYS_CONTEXT *esys_ctx,
                       TPM2_HANDLE t_handle,
                       TPM2_HANDLE p_handle,
                       const char *sh_auth)
{
    TSS2_RC         rval;
    ESYS_TR         persistent_handle;
    ESYS_TR         transient_handle;
    TPM2B_DIGEST    pwd;

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", sh_auth);

    rval = Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_TR_FromTPMPublic(esys_ctx, t_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &transient_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, transient_handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             p_handle, &persistent_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_EvictControl has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Transient object (0x%" PRIX32 ") has now been persisted at handle 0x%" PRIX32 ".\n",
          t_handle, p_handle);
    return 0;
}

int tss2_readEcpPublicKey(ESYS_CONTEXT *esys_ctx,
                          TPM2_HANDLE handle,
                          TPM2_HANDLE ses_key_handle,
                          const char *ses_key_auth,
                          BYTE *x,
                          UINT16 *x_len,
                          BYTE *y,
                          UINT16 *y_len)
{
    int             ret = 1;
    TPM2_RC         rval;
    TPM2B_NAME      *name_key_sign = NULL;
    TPM2B_NAME      *key_qualified_name = NULL;
    TPM2B_PUBLIC    *out_public = NULL;
    TPM2_HANDLE     ses_handle = ESYS_TR_NONE;
    ESYS_TR         key_handle;

    rval = Esys_TR_FromTPMPublic(esys_ctx, handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out;
    }

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    rval = Esys_ReadPublic(esys_ctx, key_handle, ses_handle, ESYS_TR_NONE,
                           ESYS_TR_NONE, &out_public, &name_key_sign,
                           &key_qualified_name);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_ReadPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    *x_len = out_public->publicArea.unique.ecc.x.size;
    memcpy(x, out_public->publicArea.unique.ecc.x.buffer, *x_len);
    *y_len = out_public->publicArea.unique.ecc.y.size;
    memcpy(y, out_public->publicArea.unique.ecc.y.buffer, *y_len);

    free(name_key_sign);
    free(key_qualified_name);
    free(out_public);

    PRINT("Read public key from handle 0x%" PRIX32 ".\n", handle);

    ret = 0;
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_readRsaPublicKey(ESYS_CONTEXT *esys_ctx,
                          TPM2_HANDLE handle,
                          TPM2_HANDLE ses_key_handle,
                          const char *ses_key_auth,
                          UINT32 *exponent,
                          BYTE *mod,
                          UINT16 *mod_len)
{
    int             ret = 1;
    TPM2B_NAME      *name_key_sign = NULL;
    TPM2B_NAME      *key_qualified_name = NULL;
    TPM2B_PUBLIC    *out_public = NULL;
    ESYS_TR         key_handle;
    TPM2_RC         rval;
    TPM2_HANDLE     ses_handle = ESYS_TR_NONE;
    UINT16          len;

    rval = Esys_TR_FromTPMPublic(esys_ctx, handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_handle);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out;
    }

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    rval = Esys_ReadPublic(esys_ctx, key_handle, ses_handle, ESYS_TR_NONE,
                           ESYS_TR_NONE, &out_public, &name_key_sign,
                           &key_qualified_name);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_ReadPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    *exponent = out_public->publicArea.parameters.rsaDetail.exponent;
    if (*exponent == 0) {
        *exponent = 65537;
    }

    len = out_public->publicArea.unique.rsa.size;

    if (len > *mod_len) {
        PRINT("tss2_readRsaPublicKey insufficient data buffer size.\n");
        goto out_free_all;
    }
    *mod_len = len;
    memcpy(mod, out_public->publicArea.unique.rsa.buffer, len);

    PRINT("Read public key from handle 0x%" PRIX32 ".\n", handle);

    ret = 0;
out_free_all:
    free(name_key_sign);
    free(key_qualified_name);
    free(out_public);
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_rsaSign(ESYS_CONTEXT *esys_ctx,
                 TPM2_HANDLE key_handle,
                 const char *key_auth,
                 TPM2_HANDLE ses_key_handle,
                 const char *ses_key_auth,
                 TPM2_ALG_ID padding_scheme,
                 TPM2_ALG_ID hash_algo,
                 const BYTE *data_in,
                 UINT16 in_len,
                 BYTE *sig,
                 UINT16 *sig_len)
{
    int                 ret = 1;
    TPMT_SIG_SCHEME     scheme = {0};
    TPM2_HANDLE         ses_handle;
    ESYS_TR             key_object;
    TPMT_SIGNATURE      *signature;
    TPM2_RC             rval;
    TPM2B_DIGEST        pwd;
    TPM2B_DIGEST        digest = {
        .size = in_len
    };
    TPMT_TK_HASHCHECK   hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {0}
    };

    if (in_len != tss2_alg2HashSize(hash_algo)) {
        PRINT("tss2_rsaSign unsupported data buffer size.\n");
        goto out;
    }

    switch (padding_scheme) {
        case TPM2_ALG_RSAPSS:
            scheme.scheme = TPM2_ALG_RSAPSS;
            scheme.details.rsapss.hashAlg = hash_algo;
            break;
        case TPM2_ALG_RSASSA:
            scheme.scheme = TPM2_ALG_RSASSA;
            scheme.details.rsassa.hashAlg = hash_algo;
            break;
        default:
            PRINT("Unknown padding scheme.\n");
            goto out;
    }

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    memcpy(digest.buffer, data_in, in_len);

    rval = Esys_TR_FromTPMPublic(esys_ctx, key_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", key_auth);

    rval = Esys_TR_SetAuth(esys_ctx, key_object, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    rval = Esys_Sign(esys_ctx, key_object,
                     ses_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                     &digest, &scheme, &hash_validation, &signature);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_Sign has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    switch (padding_scheme) {
        case TPM2_ALG_RSAPSS:
        case TPM2_ALG_RSASSA:
            if (*sig_len < signature->signature.rsassa.sig.size) {
                goto out_free_signature;
            } else {
                *sig_len = signature->signature.rsassa.sig.size;
                memcpy(sig, signature->signature.rsassa.sig.buffer, *sig_len);
            }
            break;
    }

    PRINT("Signed using RSA key from handle 0x%" PRIX32 ".\n", key_handle);

    ret = 0;
out_free_signature:
    free(signature);
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_rsaVerify(ESYS_CONTEXT *esys_ctx,
                   TPM2_HANDLE key_handle,
                   TPM2_HANDLE ses_key_handle,
                   const char *ses_key_auth,
                   TPM2_ALG_ID padding_scheme,
                   TPM2_ALG_ID hash_algo,
                   const BYTE *data_in,
                   UINT16 in_len,
                   const BYTE *sig,
                   UINT16 sig_len,
                   int *result)
{
    int                 ret = 1, mask;
    TPMT_SIGNATURE      signature = {0};
    TPM2_HANDLE         ses_handle;
    ESYS_TR             key_object;
    TPM2_RC             rval;
    TPMT_TK_VERIFIED    *validation;
    TPM2B_DIGEST        hash = {
        .size = in_len
    };

    *result = 0;
    if (in_len != tss2_alg2HashSize(hash_algo)
        || sig_len > TPM2_MAX_RSA_KEY_BYTES) {
        PRINT("tss2_rsaVerify unsupported buffer size.\n");
        goto out;
    }

    switch (padding_scheme) {
        case TPM2_ALG_RSAPSS:
            signature.sigAlg = TPM2_ALG_RSAPSS;
            signature.signature.rsapss.hash = hash_algo;
            signature.signature.rsapss.sig.size = sig_len;
            break;
        case TPM2_ALG_RSASSA:
            signature.sigAlg = TPM2_ALG_RSASSA;
            signature.signature.rsassa.hash = hash_algo;
            signature.signature.rsassa.sig.size = sig_len;
            break;
        default:
            PRINT("Unknown padding scheme.\n");
            goto out;
    }
    memcpy(signature.signature.rsassa.sig.buffer, sig, sig_len);

    /* Open encrypted session */
    if (tss2_openEncryptedSession(esys_ctx, ses_key_handle, ses_key_auth, &ses_handle)) {
        PRINT("tss2_openEncryptedSession has failed.\n");
        goto out;
    }

    memcpy(hash.buffer, data_in, in_len);

    rval = Esys_TR_FromTPMPublic(esys_ctx, key_handle, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &key_object);
    if (rval != TSS2_RC_SUCCESS) {
        PRINT("Esys_TR_FromTPMPublic has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    rval = Esys_VerifySignature(esys_ctx, key_object,
                                ses_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                                &hash, &signature, &validation);
    mask = rval & TPM2_RC_SIGNATURE;
    if (rval != TSS2_RC_SUCCESS && !mask) {
        PRINT("Esys_VerifySignature has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        goto out_close_session;
    }

    if (rval == TSS2_RC_SUCCESS) {
        *result = 1;
    }

    free(validation);

    PRINT("Signature verified using RSA key from handle 0x%" PRIX32 ".\n", key_handle);

    ret = 0;
out_close_session:
    /* Close encrypted session */
    if (tss2_closeEncryptedSession(esys_ctx, ses_handle)) {
        PRINT("tss2_closeEncryptedSession has failed.\n");
    }
out:
    return ret;
}

int tss2_setClearLock(ESYS_CONTEXT *esys_ctx,
                      TPMI_YES_NO disable)
{
    TSS2_RC rval;
    ESYS_TR rh = ESYS_TR_RH_PLATFORM;

    rval = Esys_ClearControl(esys_ctx, rh, ESYS_TR_PASSWORD,
                             ESYS_TR_NONE, ESYS_TR_NONE, disable);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        PRINT("Esys_ClearControl has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    if (disable) {
        PRINT("Disables the execution of TPM2_Clear().\n");
    } else {
        PRINT("Enable the execution of TPM2_Clear().\n");
    }

    return 0;
}

int tss2_setDictionaryLockout(ESYS_CONTEXT *esys_ctx,
                              const char *auth,
                              UINT32 max_tries,
                              UINT32 recovery_time,
                              UINT32 lockout_recovery_time)
{
    TSS2_RC      rval;
    TPM2B_DIGEST pwd;

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", auth);
    rval = Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_LOCKOUT, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_TR_SetAuth has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    rval = Esys_DictionaryAttackParameters(esys_ctx, ESYS_TR_RH_LOCKOUT,
                                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                           max_tries, recovery_time,
                                           lockout_recovery_time);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_DictionaryAttackParameters has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Successfully configured dictionary attack parameters.\n");

    return 0;
}

int tss2_setPlatformLock(ESYS_CONTEXT *esys_ctx)
{
    TSS2_RC         rval;
    ESYS_TR         auth_handle = ESYS_TR_RH_PLATFORM;
    TPMI_RH_ENABLES enable = TPM2_RH_PLATFORM;
    TPMI_YES_NO     state = TPM2_NO;

    rval = Esys_HierarchyControl(esys_ctx, auth_handle, ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE, ESYS_TR_NONE, enable, state);

    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_HierarchyControl has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Successfully disabled platform hierarchy.\n");

    return 0;
}

int tss2_shutdown(ESYS_CONTEXT *esys_ctx,
                  TPM2_SU shutdown_type)
{
    TSS2_RC rval;

    rval = Esys_Shutdown(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, shutdown_type);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_Shutdown has failed with error code: 0x%" PRIX32 "(%s).\n", rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Successfully executed TPM shutdown.\n");

    return 0;
}

int tss2_startup(ESYS_CONTEXT *esys_ctx,
                 TPM2_SU startup_type)
{
    TSS2_RC rval;

    rval = Esys_Startup(esys_ctx, startup_type);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        PRINT("Esys_Startup has failed with error code: 0x%" PRIX32 "(%s).\n", rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Successfully executed TPM startup.\n");

    return 0;
}

int tss2_takeOwnership(ESYS_CONTEXT *esys_ctx,
                       const char *sh_auth,
                       const char *eh_auth,
                       const char *l_auth) {
    TSS2_RC      rval;
    TPM2B_DIGEST pwd;

    /* Set owner password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", sh_auth);
    rval = Esys_HierarchyChangeAuth(esys_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_HierarchyChangeAuth(owner) has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    /* Set endorsement password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", eh_auth);
    rval = Esys_HierarchyChangeAuth(esys_ctx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_HierarchyChangeAuth(endorsement) has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    /* Set lockout password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", l_auth);
    rval = Esys_HierarchyChangeAuth(esys_ctx, ESYS_TR_RH_LOCKOUT, ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        PRINT("Esys_HierarchyChangeAuth(lockout) has failed with error code: 0x%" PRIX32 "(%s).\n",
              rval, Tss2_RC_Decode(rval));
        return 1;
    }

    PRINT("Successfully taken ownership of TPM.\n");
    return 0;
}
