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
#include <stdio.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "tss2_examples.h"

#ifndef TCTI_NAME_CONF
#define TCTI_NAME_CONF NULL /* Auto detect */
#endif

int snippet_1()
{
    int ret = 1;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_RC rc;
    TPM2B_DIGEST *b = NULL;

    rc = Tss2_TctiLdr_Initialize(TCTI_NAME_CONF, &tcti_ctx);
    if (TSS2_RC_SUCCESS == rc) {
        rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
        if (TSS2_RC_SUCCESS != rc) {
            goto out_tctildr_finalize;
        } else {
            rc = Esys_Startup(esys_ctx, TPM2_SU_CLEAR);
            if (rc != TPM2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
                printf("Esys_Startup failed with error code: 0x%" PRIX32 "(%s).\n", rc, Tss2_RC_Decode(rc));
                goto out_esys_finalize;
            } else {
                rc = Esys_GetRandom(esys_ctx,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    32, &b);
                if (rc != TSS2_RC_SUCCESS) {
                    printf("Esys_GetRandom failed with error code: 0x%" PRIX32 "(%s).\n", rc, Tss2_RC_Decode(rc));
                } else {
                    ret = 0;
                }

                free(b);
            }

        }
    } else {
        goto out;
    }

out_esys_finalize:
    Esys_Finalize(&esys_ctx);
out_tctildr_finalize:
    Tss2_TctiLdr_Finalize(&tcti_ctx);
out:
    return ret;
}

int snippet_2()
{
    return tss2_examples();
}

int main()
{
    if (snippet_1() || snippet_2()) {
        return 1;
    }

    return 0;
}
