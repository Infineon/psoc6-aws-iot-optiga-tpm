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
#include "mbedtls_tpm_pk.h"

int tpm_open(ESYS_CONTEXT **ctx, const char *tcti_name_conf)
{
    if (!ctx ||
        tss2_open(ctx, tcti_name_conf) ||
        tss2_startup(*ctx, TPM2_SU_CLEAR)) {
        return 1;
    }

    return 0;
}

void tpm_release(ESYS_CONTEXT **ctx)
{
    if (!ctx ||
        tss2_shutdown(*ctx, TPM2_SU_CLEAR)) {
        return;
    }

    tss2_close(ctx);
}

int tpm_factory_reset(ESYS_CONTEXT *ctx)
{
    if (tss2_nvUndefine(ctx, TPM2_NV_PROVISIONED_INDEX)) {
        return 1;
    }

    return 0;
}
