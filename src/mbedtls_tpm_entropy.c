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

#include <string.h>
#include "mbedtls/entropy_poll.h"

#include "mbedtls_tpm_pk.h"

static int platform_entropy_poll(void *data,
                                 unsigned char *output,
                                 size_t len,
                                 size_t *olen)
{
    UINT16 length = 0;
    mbedtls_tpm_context *ctx = (mbedtls_tpm_context *)data;

    if (!len || (output == NULL) || ((void *)olen == NULL)) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    length = (UINT16)len;

    if (tss2_getRandom(ctx->esys_ctx, ctx->ses_handle, ctx->ses_auth,
                       output, &length)) {
        *olen = 0;
        return MBEDTLS_ERR_PK_HW_ACCEL_FAILED;
    }

    *olen = (size_t) length;

    return 0;
}

int tpm_entropy_init(mbedtls_tpm_context *tpm_ctx,
                     mbedtls_ctr_drbg_context *drbg_ctx,
                     mbedtls_entropy_context *entropy_ctx)
{
    const char *personalization = "tpm-drbg";

    mbedtls_ctr_drbg_init(drbg_ctx);
    mbedtls_ctr_drbg_set_reseed_interval(drbg_ctx, MBEDTLS_CTR_DRBG_RESEED_INTERVAL);

    mbedtls_entropy_init(entropy_ctx);

    if (mbedtls_entropy_add_source(entropy_ctx,
                                   platform_entropy_poll, (void *)tpm_ctx, 0,
                                   MBEDTLS_ENTROPY_SOURCE_STRONG)) {
        return 1;
    }

    if (mbedtls_ctr_drbg_seed(drbg_ctx,
                              mbedtls_entropy_func,
                              entropy_ctx,
                              (const unsigned char *)personalization, strlen(personalization))) {
        return 1;
    }

    return 0;
}
