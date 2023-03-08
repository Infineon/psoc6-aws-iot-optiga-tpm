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

#include "tcti_spi_psoc6.h"

#include <stdlib.h>

#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tcti_spi_helper.h>

#define SPI_MAX_TRANSFER (4 + 64)

#ifdef ENABLE_TPM_RESET
int cy_rstdrv_init()
{
    cy_rslt_t result;

    result = cyhal_gpio_init(GPIO_RESET, CYHAL_GPIO_DIR_OUTPUT,
                             CYHAL_GPIO_DRIVE_STRONG, 0);

    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    return 0;
}

void cy_rstdrv_write(bool value)
{
    cyhal_gpio_write(GPIO_RESET, value);
}

void cy_rstdrv_release()
{
    cyhal_gpio_free(GPIO_RESET);
}
#endif

int cy_spidrv_init(cyhal_spi_t *spi)
{
    cy_rslt_t result;

    if (spi == NULL)
    {
        return 1;
    }

#ifdef ENABLE_TPM_WAIT_STATE
    /**
     * Use GPIO to drive chip-select line instead of using SPI subsystem.
     * Reason being that the PSoC SPI subsystem is unable to keep CS active
     * after completing a transmission. This is necessary
     * in TPM SPI protocol to allow the checking of wait-state
     */
    result = cyhal_gpio_init(mSPI_SS, CYHAL_GPIO_DIR_OUTPUT,
                             CYHAL_GPIO_DRIVE_STRONG, 1);

    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    result = cyhal_spi_init(spi, mSPI_MOSI, mSPI_MISO, mSPI_SCLK,
                            NC, NULL, 8, CYHAL_SPI_MODE_00_MSB, false);
#else
    result = cyhal_spi_init(spi, mSPI_MOSI, mSPI_MISO, mSPI_SCLK,
                            mSPI_SS, NULL, 8, CYHAL_SPI_MODE_00_MSB, false);
#endif

    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    result = cyhal_spi_set_frequency(spi, SPI_FREQ_HZ);

    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    cyhal_spi_enable_event(spi, 0, SPI_INTERRUPT_PRIORITY, false);

    return 0;
}

int cy_spidrv_xfer(cyhal_spi_t *spi, uint8_t *tx, uint8_t *rx, size_t len)
{
    int result = CY_RSLT_TYPE_ERROR;
    size_t tx_len = len;
    size_t rx_len = len;

    if (tx == NULL)
    {
        tx_len = 0;
    }

    if (rx == NULL)
    {
        rx_len = 0;
    }

    result = cyhal_spi_transfer(spi, tx, tx_len, rx, rx_len, 0x00);

    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    return 0;
}

void cy_spidrv_release(cyhal_spi_t *spi)
{
    if (!spi)
    {
        return;
    }

#ifdef ENABLE_TPM_WAIT_STATE
    cyhal_gpio_free(mSPI_SS);
#endif
    cyhal_spi_free(spi);
}

int cy_timerdrv_init(cyhal_timer_t *timer, cyhal_timer_event_callback_t callback, void *callback_arg)
{
    cy_rslt_t result;

    result = cyhal_timer_init(timer, NC, NULL);
    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    /* Set the frequency of timer to 10000 counts in a second */
    result = cyhal_timer_set_frequency(timer, 10000);
    if (result != CY_RSLT_SUCCESS)
    {
        cyhal_timer_free(timer);
        return 1;
    }

    /* Assign the ISR to execute on timer interrupt */
    cyhal_timer_register_callback(timer, callback, callback_arg);

    /* Set the event on which timer interrupt occurs and enable it */
    cyhal_timer_enable_event(timer, CYHAL_TIMER_IRQ_TERMINAL_COUNT, TIMER_INTERRUPT_PRIORITY, true);

    return 0;
}

int cy_timerdrv_start(cyhal_timer_t *timer, int milliseconds)
{
    cy_rslt_t result;

    const cyhal_timer_cfg_t timer_cfg =
    {
        .compare_value = 0,
        .period = (uint32_t)milliseconds*10,
        .direction = CYHAL_TIMER_DIR_UP,
        .is_compare = false,
        .is_continuous = false,
        .value = (uint32_t)0
    };

    result = cyhal_timer_configure(timer, &timer_cfg);
    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    result = cyhal_timer_reset(timer);
    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    result = cyhal_timer_start(timer);
    if (result != CY_RSLT_SUCCESS)
    {
        return 1;
    }

    return 0;
}

void cy_timerdrv_release(cyhal_timer_t *timer)
{
    cyhal_timer_free(timer);
}

TSS2_RC
platform_sleep_ms(void *user_data, int milliseconds)
{
    (void) user_data;

    Cy_SysLib_Delay(milliseconds);

    return TSS2_RC_SUCCESS;
}

static void platform_isr_timer(void *callback_arg, cyhal_timer_event_t event)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) callback_arg;

    if (event == CYHAL_TIMER_IRQ_TERMINAL_COUNT)
    {
        platform_data->isTimerExpired = true;
    }
}

TSS2_RC
platform_start_timeout(void *user_data, int milliseconds)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    platform_data->isTimerExpired = false;

    if (cy_timerdrv_start(&platform_data->timer, milliseconds))
    {
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_timeout_expired(void *user_data, bool *is_timeout_expired)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    *is_timeout_expired = platform_data->isTimerExpired;

    return TSS2_RC_SUCCESS;
}

#ifdef ENABLE_TPM_WAIT_STATE
TSS2_RC
platform_spi_acquire(void *user_data)
{
    cyhal_gpio_write(mSPI_SS, 0);
    return TSS2_RC_SUCCESS;
}

TSS2_RC
platform_spi_release(void *user_data)
{
    cyhal_gpio_write(mSPI_SS, 1);
    return TSS2_RC_SUCCESS;
}
#endif

TSS2_RC
platform_spi_transfer(void *user_data, const void *data_out, void *data_in, size_t cnt)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    /* Maximum transfer size is 64 bytes */
    if (cnt > SPI_MAX_TRANSFER)
    {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* At least one of the buffers has to be set */
    if (data_out == NULL && data_in == NULL)
    {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    /* Clear receive buffer */
    if (data_in != NULL && data_in !=  data_out)
    {
        memset (data_in, 0, cnt);
    }

    if (cy_spidrv_xfer(&platform_data->spi, (uint8_t *)data_out, data_in, cnt))
    {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}

void
platform_finalize(void *user_data)
{
    PLATFORM_USERDATA *platform_data = (PLATFORM_USERDATA *) user_data;

    cy_timerdrv_release(&platform_data->timer);
    cy_spidrv_release(&platform_data->spi);
#ifdef ENABLE_TPM_RESET
    cy_rstdrv_release();
#endif

    free(platform_data);
}

TSS2_RC
create_tcti_spi_psoc6_platform(TSS2_TCTI_SPI_HELPER_PLATFORM *platform)
{

    /* Create required platform user data */
    PLATFORM_USERDATA *platform_data = calloc (1, sizeof (PLATFORM_USERDATA));

    if (platform_data == NULL)
    {
        return TSS2_BASE_RC_MEMORY;
    }

    if (cy_timerdrv_init(&platform_data->timer, platform_isr_timer, (void *) platform_data))
    {
        goto error;
    }

    if (cy_spidrv_init(&platform_data->spi))
    {
        goto error;
    }

#ifdef ENABLE_TPM_RESET
    if (cy_rstdrv_init())
    {
        goto error;
    }

    cy_rstdrv_write(0);
    platform_sleep_ms(NULL, TPM_RESET_WARM);
    cy_rstdrv_write(1);
    platform_sleep_ms(NULL, TPM_RESET_INACTIVE);
#endif

    /* Create TCTI SPI platform struct with custom platform methods */
    platform->user_data = platform_data;
    platform->sleep_ms = platform_sleep_ms;
    platform->start_timeout = platform_start_timeout;
    platform->timeout_expired = platform_timeout_expired;
#ifdef ENABLE_TPM_WAIT_STATE
    platform->spi_acquire = platform_spi_acquire;
    platform->spi_release = platform_spi_release;
#else
    platform->spi_acquire = NULL;
    platform->spi_release = NULL;
#endif
    platform->spi_transfer = platform_spi_transfer;
    platform->finalize = platform_finalize;

    return TSS2_RC_SUCCESS;

error:

    cy_spidrv_release(&platform_data->spi);

    return TSS2_BASE_RC_IO_ERROR;
}

TSS2_RC
Tss2_Tcti_Spi_Psoc6_Init(TSS2_TCTI_CONTEXT* tcti_context, size_t* size, const char* config)
{
    (void) config;
    TSS2_RC ret = 0;
    TSS2_TCTI_SPI_HELPER_PLATFORM tcti_platform = {0};

    /* Check if context size is requested */
    if (tcti_context == NULL)
    {
        return Tss2_Tcti_Spi_Helper_Init(NULL, size, NULL);
    }

    if ((ret = create_tcti_spi_psoc6_platform(&tcti_platform)))
    {
        return ret;
    }

    /* Initialize TCTI context */
    return Tss2_Tcti_Spi_Helper_Init(tcti_context, size, &tcti_platform);
}

