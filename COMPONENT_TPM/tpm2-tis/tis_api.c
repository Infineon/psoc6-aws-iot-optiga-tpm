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

#include <src/tpm.h>
#include <tpm_tis_spi.h>
#include "tis_api.h"

struct spi_device *spidev;

int tis_init(void) {
    int rc = -1;
    spidev = malloc(sizeof(struct spi_device));
    struct device *dev = &spidev->dev;

    if (!spidev)
        return -1;

    /* Enable interrupts or SPI will not work */
    __enable_irq();

    tpm_tis_spi_probe(spidev);

    /* To obtain locality */
    rc = tpm_pm_resume(dev);
    if (rc != 0 && rc != 0x100) {
        return -1;
    }

    return 0;
}

int tis_test(void) {
    struct device *dev = &spidev->dev;
    struct tpm_chip *chip = dev_get_drvdata(dev);
    unsigned char ba[10];
    int rc = -1;

    memset(ba, 0, sizeof(ba));

    rc = tpm_pm_resume(dev);
    if (rc != 0 && rc != 0x100) {
        return -1;
    } else if (rc == 0x100) {
        /**
         * TPM Error (0x100):
         * Error (2.0): TPM_RC_INITIALIZE
         * Description: TPM not initialized by TPM2_Startup or already initialized
         *
         * This is an expected error caused by tpm_pm_suspend() without actual power cycle.
         * Thus, TPM is still initialized.
         */
        printf("Expected TPM Error 256 (0x100) due to no power cycle\r\n");
    }

    if (tpm_get_random(chip, ba, sizeof(ba)) < 0)
        return -1;

    printf("Get hardware random: Got %d bytes\r\n", sizeof(ba));
    for (int i=0;i<sizeof(ba);i++) {
        printf("%02X",ba[i]);
    }
    printf("\r\n");

    if (tpm_pm_suspend(dev))
        return -1;

    return 0;
}

void tis_release(void) {
    tpm_tis_spi_remove(spidev);
    free(spidev);
}

int tis_write(const unsigned char *buf, int size) {
    struct device *dev = &spidev->dev;
    struct tpm_chip *chip = dev_get_drvdata(dev);
    u8 *rxBuf = chip->work_space.context_buf;
    u32 *rxSize = &chip->work_space.buf_size;
    int ret;

    memcpy(rxBuf, buf, size);

    ret = tpm_transmit(chip, rxBuf, TPM_BUFSIZE);

    if (ret < 0) {
        *rxSize = 0;
        return ret;
    }

    chip->work_space.session_buf = rxBuf;
    *rxSize = ret;

    return size;
}

int tis_read(unsigned char *buf, int size) {
    struct device *dev = &spidev->dev;
    struct tpm_chip *chip = dev_get_drvdata(dev);
    u8 *rxBuf = chip->work_space.context_buf;
    u8 *rxCurPos = chip->work_space.session_buf;
    u32 *rxSize = &chip->work_space.buf_size;

    if ((u32)((u32)rxCurPos - (u32)rxBuf) + (u32)size > *rxSize)
        return -EIO;

    memcpy(buf, rxCurPos, size);
    chip->work_space.session_buf += size;

    return size;
}
