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

#include "stdlib.h"
#include "stdio.h"
#include "stdbool.h"
#include "string.h"
#include "tss2_examples.h"
#include "tss2_util.h"

#ifndef TCTI_NAME_CONF
#define TCTI_NAME_CONF NULL
#endif

#define TPM2_NV_INDEX           0x01000000

#define TPM2_HANDLE_PRIMARYKEY  0x8100beef
#define TPM2_HANDLE_RSALEAFKEY  0x8100cafe
#define TPM2_HANDLE_ECPLEAFKEY  0x8100bead

#define TPM2_AUTH_SH            "owner123"
#define TPM2_AUTH_EH            "endorsement123"
#define TPM2_AUTH_LOCKOUT       "lockout123"
#define TPM2_AUTH_SRK           "srk123"
#define TPM2_AUTH_RSALEAFKEY    "rsaleaf123"
#define TPM2_AUTH_ECPLEAFKEY     "ecleaf123"

int tss2_examples()
{
    int count, ret = 1;

    ESYS_CONTEXT *esys_ctx = NULL;

    UINT32 max_tries = 32; /* 32 retries before entering lockout */
    UINT32 recovery_time = 5; /* Every 5 secs recover 1 retry */
    UINT32 lockout_recovery_time = 300; /* 300 secs lockout */

    const BYTE nv_const[] = {0x12, 0x34, 0x56, 0x78};
    BYTE nv[sizeof(nv_const)];
    UINT16 nv_len = sizeof(nv_const);
    bool is_equal;

    BYTE rnd[TPM2_SHA256_DIGEST_SIZE];
    UINT16 rnd_len = sizeof(rnd);

    BYTE mod[TPM2_MAX_RSA_KEY_BYTES];
    UINT32 exponent;
    UINT16 mod_len = sizeof(mod);

    BYTE ecp_x[TPM2_MAX_ECC_KEY_BYTES], ecp_y[TPM2_MAX_ECC_KEY_BYTES];
    UINT16 ecp_x_len, ecp_y_len;

    BYTE cipher[TPM2_MAX_RSA_KEY_BYTES], decipher[TPM2_MAX_RSA_KEY_BYTES];
    BYTE message[TPM2_SHA256_DIGEST_SIZE];
    UINT16 cipher_len = sizeof(cipher), decipher_len = sizeof(decipher);

    int result;
    BYTE hash[TPM2_SHA256_DIGEST_SIZE];
    BYTE sig[TPM2_MAX_RSA_KEY_BYTES];
    BYTE sig_r[TPM2_MAX_ECC_KEY_BYTES], sig_s[TPM2_MAX_ECC_KEY_BYTES];
    UINT16 sig_len = sizeof(sig);
    UINT16 sig_r_len = sizeof(sig_r), sig_s_len = sizeof(sig_s);

    memset(message, 0x55, sizeof(message));
    memset(cipher, 0, sizeof(cipher));
    memset(decipher, 0, sizeof(decipher));
    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    if (tss2_open(&esys_ctx, TCTI_NAME_CONF)) {
        PRINT("tss2_open has failed.\n");
        return 1;
    }

    if (tss2_startup(esys_ctx, TPM2_SU_CLEAR)) {
        PRINT("tss2_startup has failed.\n");
        goto out;
    }

    if (tss2_setClearLock(esys_ctx, true)) {
        PRINT("tss2_setClearLock has failed.\n");
        goto out;
    }

    PRINT("tss2_forceClear is anticipated to fail here as TPM2_Clear() is disabled.\n");
    if (!tss2_forceClear(esys_ctx)) {
        PRINT("tss2_forceClear is expected to fail, but it did not.\n");
        goto out;
    }

    if (tss2_setClearLock(esys_ctx, false) || tss2_forceClear(esys_ctx)) {
        PRINT("tss2_setClearLock/tss2_forceClear has failed.\n");
        goto out;
    }

    if (tss2_takeOwnership(esys_ctx, TPM2_AUTH_SH, TPM2_AUTH_EH, TPM2_AUTH_LOCKOUT)) {
        PRINT("tss2_takeOwnership has failed.\n");
        goto out;
    }

    if (tss2_setDictionaryLockout(esys_ctx, TPM2_AUTH_LOCKOUT, max_tries,
                                  recovery_time, lockout_recovery_time)) {
        PRINT("tss2_setDictionaryLockout has failed.\n");
        goto out;
    }

    if (tss2_nvDefine(esys_ctx, TPM2_NV_INDEX, nv_len)) {
        PRINT("tss2_nvDefine has failed.\n");
        goto out;
    }

    if (tss2_getSysHandle(esys_ctx, TPM2_NV_INDEX_FIRST, &count, NULL)) {
        PRINT("tss2_getSysHandle has failed.\n");
        goto out_nv_undefine;
    }

    if (tss2_nvWrite(esys_ctx, TPM2_NV_INDEX, nv_const, sizeof(nv_const)) ||
        nv_len != sizeof(nv_const)) {
        PRINT("tss2_nvRead has failed.\n");
        goto out_nv_undefine;
    }

    if (tss2_nvRead(esys_ctx, TPM2_NV_INDEX, nv, &nv_len) ||
        nv_len != sizeof(nv_const) || memcmp(nv, nv_const, nv_len)) {
        PRINT("tss2_nvRead has failed.\n");
        goto out_nv_undefine;
    }

    if (tss2_nvCompare(esys_ctx, TPM2_NV_INDEX, nv_const, sizeof(nv_const), &is_equal) ||
        !is_equal) {
        PRINT("tss2_nvCompare has failed.\n");
        goto out_nv_undefine;
    }

    if (tss2_nvUndefine(esys_ctx, TPM2_NV_INDEX)) {
        PRINT("tss2_nvUndefine has failed.\n");
        goto out;
    }

    if (tss2_getSysHandle(esys_ctx, TPM2_NV_INDEX_FIRST, &count, NULL)) {
        PRINT("tss2_getSysHandle has failed.\n");
        goto out;
    }

#ifdef PLATFORM_LOCK_TEST
    if (tss2_setPlatformLock(esys_ctx)) {
        PRINT("tss2_setPlatformLock has failed.\n");
        goto out;
    }

    PRINT("tss2_setClearLock is anticipated to fail here as platform hierarchy is disabled.\n");
    if (!tss2_setClearLock(esys_ctx, false)) {
        PRINT("tss2_setClearLock is expected to fail, but it did not.\n");
        goto out;
    }
#endif

    if (tss2_createPrimaryKey(esys_ctx, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SH, TPM2_AUTH_SRK)) {
        PRINT("tss2_createPrimaryKey has failed.\n");
        goto out;
    }

    if (tss2_getRandom(esys_ctx, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK, rnd, &rnd_len)) {
        PRINT("tss2_getRandom has failed.\n");
        goto out;
    }

    if (tss2_createRsaKey(esys_ctx, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK,
                          TPM2_HANDLE_RSALEAFKEY, TPM2_AUTH_RSALEAFKEY)) {
        PRINT("tss2_createRsaLeafKey has failed.\n");
        goto out;
    }

    if (tss2_createEcpKey(esys_ctx, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK,
                          TPM2_HANDLE_ECPLEAFKEY, TPM2_AUTH_ECPLEAFKEY)) {
        PRINT("tss2_createEcpLeafKey has failed.\n");
        goto out;
    }

    if (tss2_readRsaPublicKey(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY,
                              TPM2_AUTH_SRK, &exponent, mod, &mod_len)) {
        PRINT("tss2_readRsaPublicKey has failed.\n");
        goto out;
    }

    if (tss2_readEcpPublicKey(esys_ctx, TPM2_HANDLE_ECPLEAFKEY, TPM2_HANDLE_PRIMARYKEY,
                              TPM2_AUTH_SRK, ecp_x, &ecp_x_len, ecp_y, &ecp_y_len)) {
        PRINT("tss2_readEcpPublicKey has failed.\n");
        goto out;
    }

    if (tss2_getSysHandle(esys_ctx, TPM2_PERSISTENT_FIRST, &count, NULL)) {
        PRINT("tss2_getSysHandle has failed.\n");
        goto out;
    }

    if (tss2_cipher(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK,
                    TPM2_ALG_RSAES, TPM2_ALG_NULL, message, sizeof(message), cipher, &cipher_len)) {
        PRINT("tss2_cipher has failed.\n");
        goto out;
    }

    if (tss2_decipher(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_AUTH_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY,
                      TPM2_AUTH_SRK, TPM2_ALG_RSAES, TPM2_ALG_NULL, cipher, cipher_len, decipher, &decipher_len)) {
        PRINT("tss2_decipher has failed.\n");
        goto out;
    }

    cipher_len = sizeof(cipher);
    if (tss2_cipher(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK, TPM2_ALG_OAEP,
                    TPM2_ALG_SHA256, message, sizeof(message), cipher, &cipher_len)) {
        PRINT("tss2_cipher has failed.\n");
        goto out;
    }

    decipher_len = sizeof(decipher);
    if (tss2_decipher(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_AUTH_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY,
                      TPM2_AUTH_SRK, TPM2_ALG_OAEP, TPM2_ALG_SHA256, cipher, cipher_len, decipher, &decipher_len)) {
        PRINT("tss2_decipher has failed.\n");
        goto out;
    }

    if (tss2_rsaSign(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_AUTH_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY,
                     TPM2_AUTH_SRK, TPM2_ALG_RSASSA, TPM2_ALG_SHA256, hash, sizeof(hash), sig, &sig_len)) {
        PRINT("tss2_rsaSign has failed.\n");
        goto out;
    }

    if (tss2_rsaVerify(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK,
                       TPM2_ALG_RSASSA, TPM2_ALG_SHA256, hash, sizeof(hash), sig, sig_len, &result)) {
        PRINT("tss2_rsaVerify has failed.\n");
        goto out;
    }

    sig_len = sizeof(sig);
    if (tss2_rsaSign(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_AUTH_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY,
                     TPM2_AUTH_SRK, TPM2_ALG_RSAPSS, TPM2_ALG_SHA256, hash, sizeof(hash), sig, &sig_len)) {
        PRINT("tss2_rsaSign has failed.\n");
        goto out;
    }

    if (tss2_rsaVerify(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK,
                       TPM2_ALG_RSAPSS, TPM2_ALG_SHA256, hash, sizeof(hash), sig, sig_len, &result)) {
        PRINT("tss2_rsaVerify has failed.\n");
        goto out;
    }

    if (tss2_ecpSign(esys_ctx, TPM2_HANDLE_ECPLEAFKEY, TPM2_AUTH_ECPLEAFKEY, TPM2_HANDLE_PRIMARYKEY,
                     TPM2_AUTH_SRK, TPM2_ALG_ECDSA, TPM2_ALG_SHA256, hash, sizeof(hash),
                     sig_r, &sig_r_len, sig_s, &sig_s_len)) {
        PRINT("tss2_ecpSign has failed.\n");
        goto out;
    }

    if (tss2_ecpVerify(esys_ctx, TPM2_HANDLE_ECPLEAFKEY, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SRK,
                       TPM2_ALG_ECDSA, TPM2_ALG_SHA256, hash, sizeof(hash),
                       sig_r, sig_r_len, sig_s, sig_s_len, &result)) {
        PRINT("tss2_ecpVerify has failed.\n");
        goto out;
    }

    if (tss2_clearPersistentHandle(esys_ctx, TPM2_HANDLE_RSALEAFKEY, TPM2_AUTH_SH)) {
        PRINT("tss2_clearPersistentHandle(TPM2_HANDLE_RSALEAFKEY) has failed.\n");
        goto out;
    }

    if (tss2_clearPersistentHandle(esys_ctx, TPM2_HANDLE_ECPLEAFKEY, TPM2_AUTH_SH)) {
        PRINT("tss2_clearPersistentHandle(TPM2_HANDLE_ECPLEAFKEY) has failed.\n");
        goto out;
    }

    if (tss2_clearPersistentHandle(esys_ctx, TPM2_HANDLE_PRIMARYKEY, TPM2_AUTH_SH)) {
        PRINT("tss2_clearPersistentHandle(TPM2_HANDLE_PRIMARYKEY) has failed.\n");
        goto out;
    }

    ret = 0;
    goto out;

out_nv_undefine:
    if (tss2_nvUndefine(esys_ctx, TPM2_NV_INDEX)) {
        ret = 1;
        PRINT("tss2_nvUndefine has failed.\n");
    }
out:
    if (tss2_shutdown(esys_ctx, TPM2_SU_CLEAR)) {
        ret = 1;
        PRINT("tss2_shutdown has failed.\n");
    }

    if (tss2_close(&esys_ctx)) {
        ret = 1;
        PRINT("tss2_close has failed.\n");
    }

    return ret;
}
