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

#include <FreeRTOS.h>
#include <task.h>
#include "stdio.h"
#include "tpm_task.h"

#include "tis_api.h"
#include "tss2_esys.h"
#include "tss2_tcti_soc.h"
#include "tpmt_api.h"
#include "mbedtls_tpmt_api.h"

#define FILE_TPMTASK "tpm_task :"

//#define TPM_FORCE_CLEAR

/******************************************************************************
 *                             Global Variables
 ******************************************************************************/
TSS2_TCTI_CONTEXT *tcti;
ESYS_CONTEXT *ectx;

/******************************************************************************
 *                        Extern Functions and Variables
 ******************************************************************************/

/*******************************************************************************
* Function Name: tpm_task
********************************************************************************
* Summary:
*
*
*******************************************************************************/
void tpm_task(void)
{
    printf("%s started\r\n", FILE_TPMTASK);

#ifndef TPM_FORCE_CLEAR
    mbedtls_pk_context pkctx;
    size_t tpmCertLen = 4096;
    uint8_t *tpmCertificate = (uint8_t *)malloc(tpmCertLen);

    if (mbedtls_tpmt_provision()) {
        printf("%s error executing mbedtls_tpmt_provision()\r\n", FILE_TPMTASK);
        return;
    }
    if (mbedtls_tpmt_pkctx_init(&pkctx)) {
        printf("%s error executing mbedtls_tpm2_pkctx_init()\r\n", FILE_TPMTASK);
        return;
    }
    if (mbedtls_tpmt_pkctx_free(&pkctx)) {
        printf("%s error executing mbedtls_tpmt_pkctx_free()\r\n", FILE_TPMTASK);
        return;
    }
    if (mbedtls_tpmt_genCsr(tpmCertificate, &tpmCertLen)) {
        printf("%s error executing mbedtls_tpmt_genCsr()\r\n", FILE_TPMTASK);
        return;
    }

    free(tpmCertificate);
#else
    tpmt_fast_clear();
#endif
}

/* [] END OF FILE */
