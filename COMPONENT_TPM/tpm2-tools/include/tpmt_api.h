/**
 * MIT License
 *
 * Copyright (c) 2021 Infineon Technologies AG
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

#ifndef TPMT_API_H_
#define TPMT_API_H_

#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>

#define TPMT_HANDLE_PRIMARYKEY 0x8100beef
#define TPMT_HANDLE_LEAFKEY 0x8100cafe

uint8_t tpmt_open(ESYS_CONTEXT **ectx);
uint8_t tpmt_close(ESYS_CONTEXT **ectx);

uint8_t tpmt_forceClear(ESYS_CONTEXT *ectx);
uint8_t tpmt_takeOwnership(ESYS_CONTEXT *ectx);
uint8_t tpmt_getRandom(ESYS_CONTEXT *ectx, uint8_t *rnd, uint16_t *len);
uint8_t tpmt_createTransientPrimaryKey(ESYS_CONTEXT *ectx);
uint8_t tpmt_createTransientLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle);
uint8_t tpmt_move2Persistent(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle, TPM2_HANDLE pHandle);
uint8_t tpmt_clearTransient(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle);
uint8_t tpmt_readPublicKey(ESYS_CONTEXT *ectx, TPM2_HANDLE handle, uint32_t *exponent, uint8_t *mod, uint16_t *modlen);
uint8_t tpmt_getSysHandle(ESYS_CONTEXT *ectx, UINT32 property, uint8_t *num_handle, TPM2_HANDLE *sys_handle1, TPM2_HANDLE *sys_handle2);
uint8_t tpmt_cipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain, uint16_t lenin, uint8_t *dataout, uint16_t *lenout);
uint8_t tpmt_decipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain, uint16_t lenin, uint8_t *dataout, uint16_t *lenout);
uint8_t tpmt_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain, uint16_t lenin, uint8_t *dataout, uint16_t *lenout);
uint8_t tpmt_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *digest, uint16_t digestlen, uint8_t *sig, uint16_t siglen, uint8_t *result);

uint8_t tpmt_fast_clear(void);
uint8_t tpmt_fast_perso(void);
uint8_t tpmt_fast_decipher(uint8_t *secret, uint16_t secretlen, uint8_t *msg, uint16_t *msglen);
uint8_t tpmt_fast_sign(uint8_t *hash, uint16_t hashlen, uint8_t *sig, uint16_t *siglen);
uint8_t tpmt_fast_getpk(uint32_t *exponent, uint8_t *mod, uint16_t *modlen);
uint8_t tpmt_fast_getRandom(uint8_t *rnd, uint16_t *len);

#endif
