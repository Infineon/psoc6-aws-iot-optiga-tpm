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

#include <tis_api.h>
#include <tss2_tcti.h>
#include <string.h>
#include <sys/types.h>
#include <tss2_mu.h>
#define LOGMODULE tcti
#include <util/log.h>
#include "tss2_tcti_soc.h"
#include "tcti-soc.h"

TSS2_RC
tcti_device_transmit (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer)
{
    TSS2_TCTI_SOC_CONTEXT *tcti_soc = (TSS2_TCTI_SOC_CONTEXT *)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = &tcti_soc->common;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    ssize_t size;

    rc = tcti_common_transmit_checks (tcti_common,
                                      command_buffer,
                                      TCTI_SOC_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    LOGBLOB_DEBUG (command_buffer,
                   command_size,
                   "sending %zu byte command buffer:",
                   command_size);
    size = tis_write(command_buffer,
                      command_size);
    if (size < 0) {
        return TSS2_TCTI_RC_IO_ERROR;
    } else if ((size_t)size != command_size) {
        LOG_ERROR ("wrong number of bytes written. Expected %zu, wrote %zd.",
                   command_size,
                   size);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_device_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout)
{
    TSS2_TCTI_SOC_CONTEXT *tcti_soc = (TSS2_TCTI_SOC_CONTEXT *)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = &tcti_soc->common;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    ssize_t size = 0;
    uint8_t header[TPM_HEADER_SIZE];
    size_t offset = 2;
    UINT32 partial_size;

    rc = tcti_common_receive_checks (tcti_common,
                                     response_size,
                                     TCTI_SOC_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }


    if (!response_buffer) {
        if (!tcti_common->partial_read_supported) {
            LOG_DEBUG("Partial read not supported ");
            *response_size = 4096;
            return TSS2_RC_SUCCESS;
        } else {
            /* Read the header only and get the response size out of it */
            LOG_DEBUG("Partial read - reading response size");

            size = tis_read(header, TPM_HEADER_SIZE);
            if (size != TPM_HEADER_SIZE) {
                return TSS2_TCTI_RC_IO_ERROR;
            }

            LOG_DEBUG("Partial read - received header");
            rc = Tss2_MU_UINT32_Unmarshal(header, TPM_HEADER_SIZE,
                                          &offset, &partial_size);
            if (rc != TSS2_RC_SUCCESS) {
                LOG_ERROR ("Failed to unmarshal response size.");
                return rc;
            }
            if (partial_size < TPM_HEADER_SIZE) {
                LOG_ERROR ("Received %zu bytes, not enough to hold a TPM2"
               " response header.", size);
                return TSS2_TCTI_RC_GENERAL_FAILURE;
            }

            LOG_DEBUG("Partial read - received response size %d.", partial_size);
            tcti_common->partial = true;
            *response_size = partial_size;
            memcpy(&tcti_common->header, header, TPM_HEADER_SIZE);
            return rc;
        }
    }

    /* In case when the whole response is just the 10 bytes header
     * and we have read it already to get the size, we don't need
     * to call poll and read again. Just copy what we have read
     * and return.
     */
    if (tcti_common->partial == true && *response_size == TPM_HEADER_SIZE) {
        memcpy(response_buffer, &tcti_common->header, TPM_HEADER_SIZE);
        tcti_common->partial = false;
        goto out;
    }

    if (tcti_common->partial == true) {
        memcpy(response_buffer, &tcti_common->header, TPM_HEADER_SIZE);
        size = tis_read(response_buffer + TPM_HEADER_SIZE, *response_size - TPM_HEADER_SIZE);
    } else {
        size = tis_read(response_buffer, *response_size);
    }
    if (size < 0) {
        LOG_ERROR ("Failed to read response from tis_read, got errno %d: %s",
           errno, strerror (errno));
        return TSS2_TCTI_RC_IO_ERROR;
    }

    if (size == 0) {
        LOG_WARNING ("Got EOF instead of response.");
        rc = TSS2_TCTI_RC_NO_CONNECTION;
        goto out;
    }

    size += tcti_common->partial ? TPM_HEADER_SIZE : 0;
    LOGBLOB_DEBUG(response_buffer, size, "Response Received");
    tcti_common->partial = false;

    if ((size_t)size < TPM_HEADER_SIZE) {
        LOG_ERROR ("Received %zu bytes, not enough to hold a TPM2 response "
                   "header.", size);
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;
        goto out;
    }

    rc = header_unmarshal (response_buffer, &tcti_common->header);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    LOG_DEBUG("Size from header %u bytes read %zu", tcti_common->header.size, size);

    if ((size_t)size != tcti_common->header.size) {
        LOG_WARNING ("TPM2 response size disagrees with number of bytes read "
                     "from tis_read. Header says %u but we read %zu bytes.",
                     tcti_common->header.size, size);
    }
    if (*response_size < tcti_common->header.size) {
        LOG_WARNING ("TPM2 response size is larger than the provided "
                     "buffer: future use of this TCTI will likely fail.");
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;
    }
    *response_size = size;
    /*
     * Executing code beyond this point transitions the state machine to
     * TRANSMIT. Another call to this function will not be possible until
     * another command is sent to the TPM.
     */
out:
    tcti_common->state = TCTI_STATE_TRANSMIT;

    return rc;
}


void
tcti_device_finalize (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_SOC_CONTEXT *tcti_soc = (TSS2_TCTI_SOC_CONTEXT *)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = &tcti_soc->common;

    if (tcti_soc == NULL) {
        return;
    }

    tcti_common->state = TCTI_STATE_FINAL;
}

TSS2_RC
tcti_device_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    /* Linux driver doesn't expose a mechanism to cancel commands. */
    (void)(tctiContext);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_device_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    /* This driver/platform does not support polling */
    (void) tctiContext;
    (void) handles;
    (void) num_handles;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_device_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    /*
     * Linux driver doesn't expose a mechanism for user space applications
     * to set locality.
     */
    (void)(tctiContext);
    (void)(locality);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}


TSS2_RC
Tss2_Tcti_Soc_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    (void)(conf);

    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_SOC_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_SOC_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_device_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_device_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_device_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = tcti_device_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = tcti_device_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = tcti_device_set_locality;
    TSS2_TCTI_MAKE_STICKY (tctiContext) = tcti_make_sticky_not_implemented;

    TSS2_TCTI_SOC_CONTEXT *tcti_soc = (TSS2_TCTI_SOC_CONTEXT *)tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = &tcti_soc->common;
    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_common->partial_read_supported = true;
    tcti_common->partial = false;

    return tis_init();
}

void Tss2_Tcti_Soc_Release (TSS2_TCTI_CONTEXT **tctiContext)
{
    free(*tctiContext);
    *tctiContext = NULL;
    return tis_release();
}

const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-soc",
    .description = "TCTI module for communication with Cypress PSoC6 interface.",
    .config_help = "Config is ignored",
    .init = Tss2_Tcti_Soc_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}


