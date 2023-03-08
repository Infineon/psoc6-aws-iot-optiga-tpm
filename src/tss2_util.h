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

#ifndef TSS2_UTIL_H_
#define TSS2_UTIL_H_

#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#define TSS2_DEFAULT_NAME_ALG          TPM2_ALG_SHA256
#define TSS2_DEFAULT_SES_AUTH_ALG      TPM2_ALG_SHA256
#define TSS2_DEFAULT_AES_KEY_BITS      128
#define TSS2_DEFAULT_RSA_KEY_BITS      2048
#define TSS2_DEFAULT_RSA_KEY_BYTES     (TSS2_DEFAULT_RSA_KEY_BITS / 8)
#define TSS2_DEFAULT_EC_CURVE          TPM2_ECC_NIST_P256

#ifdef DEBUG
#define PRINT_HEADER() printf("%s: line %d: %s(): ", __FILE__, __LINE__, __func__)
#define PRINT(...) PRINT_HEADER(); printf(__VA_ARGS__)
#define PRINT_HEADLESS(...) printf(__VA_ARGS__)
#else
#define PRINT(...)
#define PRINT_HEADLESS(...)
#endif

int tss2_clearPersistentHandle(ESYS_CONTEXT *esys_ctx,
                               TPM2_HANDLE t_handle,
                               const char *sh_auth);

int tss2_clearTransientHandle(ESYS_CONTEXT *esys_ctx,
                              TPM2_HANDLE t_handle);

int tss2_close(ESYS_CONTEXT **esys_ctx);

int tss2_createEcpKey(ESYS_CONTEXT *esys_ctx,
                      TPM2_HANDLE parent_key_handle,
                      const char *parent_key_auth,
                      TPM2_HANDLE key_handle,
                      const char *key_auth);

int tss2_createPrimaryKey(ESYS_CONTEXT *esys_ctx,
                          TPM2_HANDLE key_handle,
                          const char *sh_auth,
                          const char *srk_auth);

int tss2_createRsaKey(ESYS_CONTEXT *esys_ctx,
                      TPM2_HANDLE parent_key_handle,
                      const char *parent_key_auth,
                      TPM2_HANDLE key_handle,
                      const char *key_auth);

int tss2_cipher(ESYS_CONTEXT *esys_ctx,
                TPM2_HANDLE key_handle,
                TPM2_HANDLE ses_key_handle,
                const char *ses_key_auth,
                TPM2_ALG_ID padding_scheme,
                TPM2_ALG_ID hash_algo,
                const BYTE *data_in,
                UINT16 in_len,
                BYTE *data_out,
                UINT16 *out_len);

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
                  UINT16 *out_len);

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
                 UINT16 *s_len);

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
                   int *result);

int tss2_forceClear(ESYS_CONTEXT *esys_ctx);

int tss2_getRandom(ESYS_CONTEXT *esys_ctx,
                   TPM2_HANDLE ses_key_handle,
                   const char *ses_key_auth,
                   BYTE *rnd,
                   UINT16 *len);

int tss2_getSysHandle(ESYS_CONTEXT *esys_ctx,
                      UINT32 property,
                      int *count,
                      TPM2_HANDLE **sys_handles);

int tss2_nvCompare(ESYS_CONTEXT *esys_ctx,
                   TPM2_HANDLE nv_index,
                   const BYTE *magic,
                   UINT16 magic_len,
                   bool *is_equal);

int tss2_nvDefine(ESYS_CONTEXT *esys_ctx,
                  TPM2_HANDLE nv_index,
                  UINT16 len);

int tss2_nvUndefine(ESYS_CONTEXT *esys_ctx,
                    TPM2_HANDLE nv_index);

int tss2_nvRead(ESYS_CONTEXT *esys_ctx,
                TPM2_HANDLE nv_index,
                BYTE *data,
                UINT16 *len);

int tss2_nvWrite(ESYS_CONTEXT *esys_ctx,
                 TPM2_HANDLE nv_index,
                 const BYTE *data,
                 UINT16 len);

int tss2_open(ESYS_CONTEXT **esys_ctx,
              const char *tcti_name_conf);

int tss2_persistHandle(ESYS_CONTEXT *esys_ctx,
                       TPM2_HANDLE t_handle,
                       TPM2_HANDLE p_handle,
                       const char *sh_auth);

int tss2_readEcpPublicKey(ESYS_CONTEXT *esys_ctx,
                          TPM2_HANDLE handle,
                          TPM2_HANDLE ses_key_handle,
                          const char *ses_key_auth,
                          BYTE *x,
                          UINT16 *x_len,
                          BYTE *y,
                          UINT16 *y_len);

int tss2_readRsaPublicKey(ESYS_CONTEXT *esys_ctx,
                          TPM2_HANDLE handle,
                          TPM2_HANDLE ses_key_handle,
                          const char *ses_key_auth,
                          UINT32 *exponent,
                          BYTE *mod,
                          UINT16 *mod_len);

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
                 UINT16 *sig_len);

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
                   int *result);

int tss2_setClearLock(ESYS_CONTEXT *esys_ctx,
                      TPMI_YES_NO disable);

int tss2_setDictionaryLockout(ESYS_CONTEXT *esys_ctx,
                              const char *auth,
                              UINT32 max_tries,
                              UINT32 recovery_time,
                              UINT32 lockout_recovery_time);

int tss2_setPlatformLock(ESYS_CONTEXT *esys_ctx);

int tss2_shutdown(ESYS_CONTEXT *esys_ctx,
                  TPM2_SU shutdown_type);

int tss2_startup(ESYS_CONTEXT *esys_ctx,
                 TPM2_SU startup_type);

int tss2_takeOwnership(ESYS_CONTEXT *esys_ctx,
                       const char *sh_auth,
                       const char *eh_auth,
                       const char *l_auth);

#endif /* TSS2_UTIL_H_ */
