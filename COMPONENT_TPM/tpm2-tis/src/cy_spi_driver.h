/******************************************************************************
 * cy_spi_driver.h
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

#ifndef SPI_DRIVER_H_
#define SPI_DRIVER_H_

#include <stdlib.h>
#include <linux/spi/spi.h>
#include "cyhal.h"

/***************************************
*            Constants
****************************************/
#define SPI_FREQ_HZ                (100000UL) // 3.3V up to 38MHz; 1.8V up to 18.5MHz

#ifdef TARGET_CY8CPROTO_062_4343W
    #define mSPI_MOSI                  P6_0
    #define mSPI_MISO                  P6_1
    #define mSPI_SCLK                  P6_2
    #define mSPI_SS                    P6_3
#else
    #error "Please configure SPI pins"
#endif

int cy_spidrv_init(struct spi_device *dev);
int cy_spidrv_xfer(struct spi_device *dev, struct spi_transfer *xfer);
void cy_spidrv_release(struct spi_device *dev);


#endif /* SPI_DRIVER_H_ */
