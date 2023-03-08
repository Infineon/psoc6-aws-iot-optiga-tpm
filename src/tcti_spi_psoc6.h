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

#ifndef TCTI_SPI_PSOC6_H_
#define TCTI_SPI_PSOC6_H_

#include <tss2/tss2_tctildr.h>
#include "cyhal.h"

/***************************************
*            Constants
****************************************/
#define TIMER_INTERRUPT_PRIORITY   0
#define SPI_INTERRUPT_PRIORITY     0
#define SPI_FREQ_HZ                (100000UL)
#define TPM_RESET_WARM             1     /* Warm Reset in msecs (t_WRST) */
#define TPM_RESET_INACTIVE         60    /* Reset Inactive Time in msecs (t_RSTIN) */

#define ENABLE_TPM_RESET
//#define ENABLE_TPM_WAIT_STATE

#if (CY_TARGET_BOARD == APP_CY8CPROTO_062_4343W)
    #define mSPI_MOSI                  P6_0
    #define mSPI_MISO                  P6_1
    #define mSPI_SCLK                  P6_2
    #define mSPI_SS                    P6_3
    #define GPIO_RESET                 P9_0
#else
    #error "SPI pins configuration is missing."
#endif

typedef struct {
    bool isTimerExpired;
    cyhal_timer_t timer;
    cyhal_spi_t spi;
} PLATFORM_USERDATA;

TSS2_RC Tss2_Tcti_Spi_Psoc6_Init(TSS2_TCTI_CONTEXT*, size_t*, const char*);

#endif /* TCTI_SPI_PSOC6_H_ */
