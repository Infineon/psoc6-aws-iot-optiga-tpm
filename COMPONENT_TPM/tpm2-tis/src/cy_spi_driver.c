/******************************************************************************
 * cy_spi_driver.c
 *
 *  Created on: Sep 8, 2020
 *      Author: wenxin.leong@infineon.com
 *
*******************************************************************************
* (c) 2019-2020, Cypress Semiconductor Corporation. All rights reserved.
*******************************************************************************
* This software, including source code, documentation and related materials
* ("Software"), is owned by Cypress Semiconductor Corporation or one of its
* subsidiaries ("Cypress") and is protected by and subject to worldwide patent
* protection (United States and foreign), United States copyright laws and
* international treaty provisions. Therefore, you may use this Software only
* as provided in the license agreement accompanying the software package from
* which you obtained this Software ("EULA").
*
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software source
* code solely for use in connection with Cypress's integrated circuit products.
* Any reproduction, modification, translation, compilation, or representation
* of this Software except as specified above is prohibited without the express
* written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer of such
* system or application assumes all risk of such use and in doing so agrees to
* indemnify Cypress against all liability.
*******************************************************************************/

#include "cy_spi_driver.h"

int cy_spidrv_init(struct spi_device *dev) {
    cy_rslt_t result;
    cyhal_spi_t *mSPI = NULL;

    mSPI = malloc(sizeof(cyhal_spi_t));

    if (mSPI == NULL)
    {
        return -1;
    }

    /**
     * Use GPIO to drive chip-select line instead of using SPI subsystem.
     * Reason being that the PSoC SPI subsystem is unable to keep CS active
     * after completing a transmission. This is necessary
     * in TPM SPI protocol to allow the checking of wait-state
     */
    result = cyhal_gpio_init( mSPI_SS, CYHAL_GPIO_DIR_OUTPUT,
                              CYHAL_GPIO_DRIVE_STRONG, 1);
    if (result != CY_RSLT_SUCCESS)
    {
        return -1;
    }

    result = cyhal_spi_init( mSPI, mSPI_MOSI, mSPI_MISO, mSPI_SCLK,
                             NC, NULL, 8, CYHAL_SPI_MODE_00_MSB, false);

    if (result != CY_RSLT_SUCCESS)
    {
        return -1;
    }

    result = cyhal_spi_set_frequency( mSPI, SPI_FREQ_HZ);

    if (result != CY_RSLT_SUCCESS)
    {
        return -1;
    }

    dev->controller = mSPI;

    return 0;
}

int cy_spidrv_xfer(struct spi_device *dev, struct spi_transfer *xfer)
{
    int result = CY_RSLT_TYPE_ERROR;
    cyhal_spi_t *mSPI = (cyhal_spi_t *) dev->controller;
    size_t tx_len = xfer->len;
    size_t rx_len = xfer->len;

    cyhal_gpio_write(mSPI_SS, 0);

    if (xfer->delay.unit == SPI_DELAY_UNIT_USECS)
        Cy_SysLib_DelayUs(xfer->delay.unit);

    if (xfer->tx_buf == NULL)
        tx_len = 0;

    if (xfer->rx_buf == NULL)
        rx_len = 0;

    result = cyhal_spi_transfer(mSPI, xfer->tx_buf, tx_len, xfer->rx_buf, rx_len, 0x00);

    if (result != CY_RSLT_SUCCESS)
    {
        return -1;
    }

    if (!xfer->cs_change)
        cyhal_gpio_write(mSPI_SS, 1);

    return 0;
}

void cy_spidrv_release(struct spi_device *dev) {
    cyhal_spi_t *mSPI = (cyhal_spi_t *) dev->controller;

    if (!mSPI)
        return;

    cyhal_gpio_free(mSPI_SS);
    cyhal_spi_free(mSPI);

    free(mSPI);
}
