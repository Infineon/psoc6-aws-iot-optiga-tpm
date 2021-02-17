/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Infineon Technologies AG
 * Copyright (C) 2016 STMicroelectronics SAS
 */

#ifndef TPM_TIS_SPI_H
#define TPM_TIS_SPI_H

#include "tpm_tis_core.h"

struct tpm_tis_spi_phy {
    struct tpm_tis_data priv;
    struct spi_device *spi_device;
    int (*flow_control)(struct tpm_tis_spi_phy *phy,
                 struct spi_transfer *xfer);

    u8 *iobuf;
};

static inline struct tpm_tis_spi_phy *to_tpm_tis_spi_phy(struct tpm_tis_data *data)
{
    return container_of(data, struct tpm_tis_spi_phy, priv);
}

extern int tpm_tis_spi_probe(struct spi_device *dev);
extern void tpm_tis_spi_remove(struct spi_device *dev);

#endif
