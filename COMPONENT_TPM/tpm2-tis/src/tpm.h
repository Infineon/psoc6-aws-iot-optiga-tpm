/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004 IBM Corporation
 * Copyright (C) 2015 Intel Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * Maintained by: <tpmdd-devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 */

#ifndef __TPM_H__
#define __TPM_H__

#include <linux/tpm.h>
#include <linux/spi/spi.h>
#include <linux/device.h>

extern const struct tpm_tis_phy_ops tpm_spi_phy_ops;
extern const struct tpm_class_ops tpm_tis_ops;
extern struct tpm_chip tpm_tis_chip;

#define TPM_MINOR       224 /* officially assigned */
#define TPM_BUFSIZE     4096
#define TPM_NUM_DEVICES     65536
#define TPM_RETRY       50

enum tpm_timeout {
    TPM_TIMEOUT = 5,    /* msecs */
    TPM_TIMEOUT_RETRY = 100, /* msecs */
    TPM_TIMEOUT_RANGE_US = 300,    /* usecs */
    TPM_TIMEOUT_POLL = 1,    /* msecs */
    TPM_TIMEOUT_USECS_MIN = 100,      /* usecs */
    TPM_TIMEOUT_USECS_MAX = 500      /* usecs */
};

#define TPM_ERR_DEACTIVATED     0x6
#define TPM_ERR_DISABLED        0x7

/* TPM2 specific constants. */
#define TPM2_SPACE_BUFFER_SIZE      16384 /* 16 kB */

/* 128 bytes is an arbitrary cap. This could be as large as TPM_BUFSIZE - 18
 * bytes, but 128 is still a relatively large number of random bytes and
 * anything much bigger causes users of struct tpm_cmd_t to start getting
 * compiler warnings about stack frame size. */
#define TPM_MAX_RNG_DATA    128

static inline void tpm_msleep(unsigned int delay_msec)
{
    usleep_range((delay_msec * 1000) - TPM_TIMEOUT_RANGE_US,
             delay_msec * 1000);
};

/* tpm-chip.c */
int tpm_chip_start(struct tpm_chip *chip);
void tpm_chip_stop(struct tpm_chip *chip);
struct tpm_chip *tpm_find_get_ops(struct tpm_chip *chip);
void tpm_put_ops(struct tpm_chip *chip);

struct tpm_chip *tpm_chip_alloc(struct device *dev,
                                const struct tpm_class_ops *ops);
struct tpm_chip *tpmm_chip_alloc(struct device *pdev,
                                 const struct tpm_class_ops *ops);
int tpm_chip_register(struct tpm_chip *chip);
void tpm_chip_unregister(struct tpm_chip *chip);

/* tpm2-cmd.c */
unsigned long tpm2_calc_ordinal_duration(struct tpm_chip *chip, u32 ordinal);
int tpm2_probe(struct tpm_chip *chip);
void tpm2_shutdown(struct tpm_chip *chip, u16 shutdown_type);
int tpm2_startup_st(struct tpm_chip *chip);
int tpm2_auto_startup(struct tpm_chip *chip);
ssize_t tpm2_get_pcr_allocation(struct tpm_chip *chip);
int tpm2_get_random(struct tpm_chip *chip, u8 *dest, size_t max);

/* tpm2-interface.c */
int tpm_pm_suspend(struct device *dev);
int tpm_pm_resume(struct device *dev);
int tpm_auto_startup(struct tpm_chip *chip);
ssize_t tpm_transmit(struct tpm_chip *chip, u8 *buf, size_t bufsiz);
ssize_t tpm_transmit_cmd(struct tpm_chip *chip, struct tpm_buf *buf,
                         size_t min_rsp_body_length, const char *desc);
int tpm_get_random(struct tpm_chip *chip, u8 *data, size_t max);

/* tpm2-space.c */
int tpm2_init_space(struct tpm_space *space, unsigned int buf_size);
void tpm2_del_space(struct tpm_chip *chip, struct tpm_space *space);

#endif
