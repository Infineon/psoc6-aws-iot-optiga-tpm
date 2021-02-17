// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2005, 2006 IBM Corporation
 * Copyright (C) 2014, 2015 Intel Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * Maintained by: <tpmdd-devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 *
 * This device driver implements the TPM interface as defined in
 * the TCG TPM Interface Spec version 1.2, revision 1.0.
 */

#include "tpm_tis_core.h"

struct tpm_tis_data tpm_data;

static void tpm_tis_clkrun_enable(struct tpm_chip *chip, bool value);

static int wait_for_tpm_stat(struct tpm_chip *chip, u8 mask,
        unsigned long timeout, wait_queue_head_t *queue,
        bool check_cancel)
{
    (void)queue;
    unsigned long stop, time = 0;
    u8 status;

    /* check current status */
    status = chip->ops->status(chip);
    if ((status & mask) == mask)
        return 0;

    stop = timeout;

    do {
        usleep_range(TPM_TIMEOUT_USECS_MIN,
                 TPM_TIMEOUT_USECS_MAX);
        status = chip->ops->status(chip);
        if ((status & mask) == mask)
            return 0;

        time += TPM_TIMEOUT_USECS_MAX;
    } while (time < stop);

    return -ETIME;
}

/* Before we attempt to access the TPM we must see that the valid bit is set.
 * The specification says that this bit is 0 at reset and remains 0 until the
 * 'TPM has gone through its self test and initialization and has established
 * correct values in the other bits.'
 */
static int wait_startup(struct tpm_chip *chip, int l)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    unsigned long time = 0;
    unsigned long stop = chip->timeout_a;

    do {
        int rc;
        u8 access = 0;

        rc = tpm_tis_read8(priv, TPM_ACCESS(l), &access);
        if (rc < 0)
            return rc;

        if (access & TPM_ACCESS_VALID)
            return 0;

        tpm_msleep(TPM_TIMEOUT);
        time += TPM_TIMEOUT;
    } while (time < stop);
    return -1;
}

static bool check_locality(struct tpm_chip *chip, int l)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    int rc;
    u8 access = 0;

    rc = tpm_tis_read8(priv, TPM_ACCESS(l), &access);
    if (rc < 0)
        return false;

    if ((access & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) ==
        (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
        priv->locality = l;
        return true;
    }

    return false;
}

static bool locality_inactive(struct tpm_chip *chip, int l)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    int rc;
    u8 access = 0;

    rc = tpm_tis_read8(priv, TPM_ACCESS(l), &access);
    if (rc < 0)
        return false;

    if ((access & (TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY))
        == TPM_ACCESS_VALID)
        return true;

    return false;
}

static int release_locality(struct tpm_chip *chip, int l)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    unsigned long time = 0;
    unsigned long stop = chip->timeout_a;

    tpm_tis_write8(priv, TPM_ACCESS(l), TPM_ACCESS_ACTIVE_LOCALITY);

    do {
        if (locality_inactive(chip, l))
            return 0;
        tpm_msleep(TPM_TIMEOUT);
        time += TPM_TIMEOUT;
    } while (time < stop);

    return -1;
}

static int request_locality(struct tpm_chip *chip, int l)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    unsigned long time = 0;
    unsigned long stop = chip->timeout_a;
    long rc;

    if (check_locality(chip, l))
        return l;

    rc = tpm_tis_write8(priv, TPM_ACCESS(l), TPM_ACCESS_REQUEST_USE);
    if (rc < 0)
        return rc;

    /* wait for burstcount */
    do {
        if (check_locality(chip, l))
            return l;
        tpm_msleep(TPM_TIMEOUT);
        time += TPM_TIMEOUT;
    } while (time < stop);

    return -1;
}

static u8 tpm_tis_status(struct tpm_chip *chip)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    int rc;
    u8 status = 0;

    rc = tpm_tis_read8(priv, TPM_STS(priv->locality), &status);
    if (rc < 0)
        return 0;

    return status;
}

static void tpm_tis_ready(struct tpm_chip *chip)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    /* this causes the current command to be aborted */
    tpm_tis_write8(priv, TPM_STS(priv->locality), TPM_STS_COMMAND_READY);
}

static int get_burstcount(struct tpm_chip *chip)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    unsigned long stop, time = 0;
    int burstcnt, rc;
    u32 value = 0;

    /* wait for burstcount */
    if (chip->flags & TPM_CHIP_FLAG_TPM2)
        stop = chip->timeout_a;
    else
        stop = chip->timeout_d;
    do {
        rc = tpm_tis_read32(priv, TPM_STS(priv->locality), &value);
        if (rc < 0)
            return rc;

        burstcnt = (value >> 8) & 0xFFFF;
        if (burstcnt)
            return burstcnt;
        usleep_range(TPM_TIMEOUT_USECS_MIN, TPM_TIMEOUT_USECS_MAX);
        time += TPM_TIMEOUT_USECS_MAX;
    } while (time < stop);
    return -EBUSY;
}

static int recv_data(struct tpm_chip *chip, u8 *buf, size_t count)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    int size = 0, burstcnt, rc;

    while (size < count) {
        rc = wait_for_tpm_stat(chip, TPM_STS_DATA_AVAIL | TPM_STS_VALID,
                 chip->timeout_c, NULL, true);
        if (rc < 0)
            return rc;
        burstcnt = get_burstcount(chip);
        if (burstcnt < 0) {
            dev_err(&chip->dev, "Unable to read burstcount\n");
            return burstcnt;
        }
        burstcnt = min_t(int, burstcnt, count - size);

        rc = tpm_tis_read_bytes(priv, TPM_DATA_FIFO(priv->locality),
                    burstcnt, buf + size);
        if (rc < 0)
            return rc;

        size += burstcnt;
    }
    return size;
}

static int tpm_tis_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
    int size = 0;
    int status;
    u32 expected;

    if (count < TPM_HEADER_SIZE) {
        size = -EIO;
        goto out;
    }

    size = recv_data(chip, buf, TPM_HEADER_SIZE);
    /* read first 10 bytes, including tag, paramsize, and result */
    if (size < TPM_HEADER_SIZE) {
        dev_err(&chip->dev, "Unable to read header\n");
        goto out;
    }

    expected = be32_to_cpu(*(__be32 *) (buf + 2));
    if (expected > count || expected < TPM_HEADER_SIZE) {
        size = -EIO;
        goto out;
    }

    size += recv_data(chip, &buf[TPM_HEADER_SIZE],
              expected - TPM_HEADER_SIZE);
    if (size < expected) {
        dev_err(&chip->dev, "Unable to read remainder of result\n");
        size = -ETIME;
        goto out;
    }

    if (wait_for_tpm_stat(chip, TPM_STS_VALID, chip->timeout_c,
                NULL, false) < 0) {
        size = -ETIME;
        goto out;
    }
    status = tpm_tis_status(chip);
    if (status & TPM_STS_DATA_AVAIL) {    /* retry? */
        dev_err(&chip->dev, "Error left over data\n");
        size = -EIO;
        goto out;
    }

out:
    tpm_tis_ready(chip);
    return size;
}

/*
 * If interrupts are used (signaled by an irq set in the vendor structure)
 * tpm.c can skip polling for the data to be available as the interrupt is
 * waited for here
 */
static int tpm_tis_send_data(struct tpm_chip *chip, const u8 *buf, size_t len)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    int rc, status, burstcnt;
    size_t count = 0;

    status = tpm_tis_status(chip);
    if ((status & TPM_STS_COMMAND_READY) == 0) {
        tpm_tis_ready(chip);
        if (wait_for_tpm_stat
            (chip, TPM_STS_COMMAND_READY, chip->timeout_b,
             NULL, false) < 0) {
            rc = -ETIME;
            goto out_err;
        }
    }

    while (count < len - 1) {
        burstcnt = get_burstcount(chip);
        if (burstcnt < 0) {
            dev_err(&chip->dev, "Unable to read burstcount\n");
            rc = burstcnt;
            goto out_err;
        }
        burstcnt = min_t(int, burstcnt, len - count - 1);
        rc = tpm_tis_write_bytes(priv, TPM_DATA_FIFO(priv->locality),
                     burstcnt, buf + count);
        if (rc < 0)
            goto out_err;

        count += burstcnt;

        if (wait_for_tpm_stat(chip, TPM_STS_VALID, chip->timeout_c,
                    NULL, false) < 0) {
            rc = -ETIME;
            goto out_err;
        }
        status = tpm_tis_status(chip);
        if ((status & TPM_STS_DATA_EXPECT) == 0) {
            rc = -EIO;
            goto out_err;
        }
    }

    /* write last byte */
    rc = tpm_tis_write8(priv, TPM_DATA_FIFO(priv->locality), buf[count]);
    if (rc < 0)
        goto out_err;

    if (wait_for_tpm_stat(chip, TPM_STS_VALID, chip->timeout_c,
                NULL, false) < 0) {
        rc = -ETIME;
        goto out_err;
    }
    status = tpm_tis_status(chip);
    if ((status & TPM_STS_DATA_EXPECT) != 0) {
        rc = -EIO;
        goto out_err;
    }

    return 0;

out_err:
    tpm_tis_ready(chip);
    return rc;
}

/*
 * If interrupts are used (signaled by an irq set in the vendor structure)
 * tpm.c can skip polling for the data to be available as the interrupt is
 * waited for here
 */
static int tpm_tis_send_main(struct tpm_chip *chip, const u8 *buf, size_t len)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    int rc;

    rc = tpm_tis_send_data(chip, buf, len);
    if (rc < 0)
        return rc;

    /* go and do it */
    rc = tpm_tis_write8(priv, TPM_STS(priv->locality), TPM_STS_GO);
    if (rc < 0)
        goto out_err;

    return 0;
out_err:
    tpm_tis_ready(chip);
    return rc;
}

static int tpm_tis_send(struct tpm_chip *chip, u8 *buf, size_t len)
{
    return tpm_tis_send_main(chip, buf, len);
}

static void tpm_tis_update_durations(struct tpm_chip *chip,
                     unsigned long *duration_cap)
{
    dev_err("%s: not implemented, it is not for tpm2.\n", __func__);
}

static void tpm_tis_update_timeouts(struct tpm_chip *chip,
                    unsigned long *timeout_cap)
{
    dev_err("%s: not implemented, it is not for tpm2.\n", __func__);
}

/*
 * Early probing for iTPM with STS_DATA_EXPECT flaw.
 * Try sending command without itpm flag set and if that
 * fails, repeat with itpm flag set.
 */
static int probe_itpm(struct tpm_chip *chip)
{
    (void)chip;
    // for Intel TPM only
    return 0;
}

static bool tpm_tis_req_canceled(struct tpm_chip *chip, u8 status)
{
    (void)chip;
    (void)status;
    return (status == TPM_STS_COMMAND_READY);
}

void tpm_tis_remove(struct tpm_chip *chip)
{
    struct tpm_tis_data *priv = dev_get_drvdata(&chip->dev);
    u32 reg = TPM_INT_ENABLE(priv->locality);
    u32 interrupt;
    int rc;

    tpm_tis_clkrun_enable(chip, true);

    rc = tpm_tis_read32(priv, reg, &interrupt);
    if (rc < 0)
        interrupt = 0;

    tpm_tis_write32(priv, reg, ~TPM_GLOBAL_INT_ENABLE & interrupt);

    tpm_tis_clkrun_enable(chip, false);
}

/**
 * tpm_tis_clkrun_enable() - Keep clkrun protocol disabled for entire duration
 *                           of a single TPM command
 * @chip:    TPM chip to use
 * @value:    1 - Disable CLKRUN protocol, so that clocks are free running
 *        0 - Enable CLKRUN protocol
 * Call this function directly in tpm_tis_remove() in error or driver removal
 * path, since the chip->ops is set to NULL in tpm_chip_unregister().
 */
static void tpm_tis_clkrun_enable(struct tpm_chip *chip, bool value)
{
    (void)chip;
    (void)value;
    // Not CONFIG_X86 so directly return
    return;
}

const struct tpm_class_ops tpm_tis = {
    .flags = TPM_OPS_AUTO_STARTUP,
    .status = tpm_tis_status,
    .recv = tpm_tis_recv,
    .send = tpm_tis_send,
    .cancel = tpm_tis_ready,
    .update_timeouts = tpm_tis_update_timeouts,
    .update_durations = tpm_tis_update_durations,
    .req_complete_mask = TPM_STS_DATA_AVAIL | TPM_STS_VALID,
    .req_complete_val = TPM_STS_DATA_AVAIL | TPM_STS_VALID,
    .req_canceled = tpm_tis_req_canceled,
    .request_locality = request_locality,
    .relinquish_locality = release_locality,
    .clk_enable = tpm_tis_clkrun_enable,
};

int tpm_tis_core_init(struct device *dev, struct tpm_tis_data *priv, int irq,
                      const struct tpm_tis_phy_ops *phy_ops,
                      acpi_handle acpi_dev_handle)
{
    u32 vendor = 0;
    u32 intfcaps = 0;
    u32 intmask;
    u8 rid = 0;
    int rc, probe;
    struct tpm_chip *chip;

    chip = tpmm_chip_alloc(dev, &tpm_tis);
    if (IS_ERR(chip))
        return PTR_ERR(chip);

    /* Maximum timeouts */
    chip->timeout_a = msecs_to_jiffies(TIS_TIMEOUT_A_MAX);
    chip->timeout_b = msecs_to_jiffies(TIS_TIMEOUT_B_MAX);
    chip->timeout_c = msecs_to_jiffies(TIS_TIMEOUT_C_MAX);
    chip->timeout_d = msecs_to_jiffies(TIS_TIMEOUT_D_MAX);
    priv->phy_ops = phy_ops;
    dev_set_drvdata(&chip->dev, priv);

    if (wait_startup(chip, 0) != 0) {
        rc = -ENODEV;
        goto out_err;
    }

    /* Take control of the TPM's interrupt hardware and shut it off */
    rc = tpm_tis_read32(priv, TPM_INT_ENABLE(0), &intmask);
    if (rc < 0)
        goto out_err;

    intmask |= TPM_INTF_CMD_READY_INT | TPM_INTF_LOCALITY_CHANGE_INT |
           TPM_INTF_DATA_AVAIL_INT | TPM_INTF_STS_VALID_INT;
    intmask &= ~TPM_GLOBAL_INT_ENABLE;
    tpm_tis_write32(priv, TPM_INT_ENABLE(0), intmask);

    rc = tpm_chip_start(chip);
    if (rc)
        goto out_err;

    rc = tpm2_probe(chip);
    tpm_chip_stop(chip);
    if (rc)
        goto out_err;

    rc = tpm_tis_read32(priv, TPM_DID_VID(0), &vendor);
    if (rc < 0)
        goto out_err;

    priv->manufacturer_id = vendor;

    rc = tpm_tis_read8(priv, TPM_RID(0), &rid);
    if (rc < 0)
        goto out_err;

    dev_info(dev, "%s TPM (device-id 0x%X, rev-id %d)\n",
         (chip->flags & TPM_CHIP_FLAG_TPM2) ? "2.0" : "1.2",
         vendor >> 16, rid);

    probe = probe_itpm(chip);
    if (probe < 0) {
        rc = -ENODEV;
        goto out_err;
    }

    /* Figure out the capabilities */
    rc = tpm_tis_read32(priv, TPM_INTF_CAPS(priv->locality), &intfcaps);
    if (rc < 0)
        goto out_err;

    dev_dbg(dev, "TPM interface capabilities (0x%x):\n",
        intfcaps);
    if (intfcaps & TPM_INTF_BURST_COUNT_STATIC)
        dev_dbg(dev, "\tBurst Count Static\n");
    if (intfcaps & TPM_INTF_CMD_READY_INT)
        dev_dbg(dev, "\tCommand Ready Int Support\n");
    if (intfcaps & TPM_INTF_INT_EDGE_FALLING)
        dev_dbg(dev, "\tInterrupt Edge Falling\n");
    if (intfcaps & TPM_INTF_INT_EDGE_RISING)
        dev_dbg(dev, "\tInterrupt Edge Rising\n");
    if (intfcaps & TPM_INTF_INT_LEVEL_LOW)
        dev_dbg(dev, "\tInterrupt Level Low\n");
    if (intfcaps & TPM_INTF_INT_LEVEL_HIGH)
        dev_dbg(dev, "\tInterrupt Level High\n");
    if (intfcaps & TPM_INTF_LOCALITY_CHANGE_INT)
        dev_dbg(dev, "\tLocality Change Int Support\n");
    if (intfcaps & TPM_INTF_STS_VALID_INT)
        dev_dbg(dev, "\tSts Valid Int Support\n");
    if (intfcaps & TPM_INTF_DATA_AVAIL_INT)
        dev_dbg(dev, "\tData Avail Int Support\n");

    rc = tpm_chip_register(chip);
    if (rc)
        goto out_err;

    return 0;
out_err:

    tpm_tis_remove(chip);

    return rc;
}

