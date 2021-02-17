// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2004 IBM Corporation
 * Copyright (C) 2014 Intel Corporation
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
 *
 * Note, the TPM chip is not interrupt driven (only polling)
 * and can have very long timeouts (minutes!). Hence the unusual
 * calls to msleep.
 */

#include "tpm.h"

/**
 * tpm_calc_ordinal_duration() - calculate the maximum command duration
 * @chip:    TPM chip to use.
 * @ordinal: TPM command ordinal.
 *
 * The function returns the maximum amount of time the chip could take
 * to return the result for a particular ordinal in jiffies.
 *
 * Return: A maximal duration time for an ordinal in jiffies.
 */
unsigned long tpm_calc_ordinal_duration(struct tpm_chip *chip, u32 ordinal)
{
    return tpm2_calc_ordinal_duration(chip, ordinal);
}

static ssize_t tpm_try_transmit(struct tpm_chip *chip, void *buf, size_t bufsiz)
{
    struct tpm_header *header = buf;
    int rc;
    ssize_t len = 0;
    u32 count, ordinal;
    unsigned long stop, time = 0;

    if (bufsiz < TPM_HEADER_SIZE)
        return -EINVAL;

    if (bufsiz > TPM_BUFSIZE)
        bufsiz = TPM_BUFSIZE;

    count = be32_to_cpu(header->length);
    ordinal = be32_to_cpu(header->ordinal);
    if (count == 0)
        return -ENODATA;
    if (count > bufsiz) {
        dev_err(&chip->dev, "invalid count value %x %zx\n", count, bufsiz);
        return -E2BIG;
    }

    rc = chip->ops->send(chip, buf, count);
    if (rc < 0) {
        if (rc != -EPIPE)
            dev_err(&chip->dev, "%s: send(): error %d\n", __func__, rc);
        return rc;
    }

    /* A sanity check. send() should just return zero on success e.g.
     * not the command length.
     */
    if (rc > 0) {
        dev_warn(&chip->dev, "%s: send(): invalid value %d\n", __func__, rc);
        rc = 0;
    }

    stop = tpm_calc_ordinal_duration(chip, ordinal);
    do {
        u8 status = chip->ops->status(chip);
        if ((status & chip->ops->req_complete_mask) ==
            chip->ops->req_complete_val)
            goto out_recv;

        if (chip->ops->req_canceled(chip, status)) {
            dev_err(&chip->dev, "Operation Canceled\n");
            return -ECANCELED;
        }

        tpm_msleep(TPM_TIMEOUT_POLL);
        rmb();
        time += TPM_TIMEOUT_POLL;
    } while (time < stop);

    chip->ops->cancel(chip);
    dev_err(&chip->dev, "Operation Timed out\n");
    return -ETIME;

out_recv:
    len = chip->ops->recv(chip, buf, bufsiz);
    if (len < 0) {
        rc = len;
        dev_err(&chip->dev, "tpm_transmit: tpm_recv: error %d\n", rc);
    } else if (len < TPM_HEADER_SIZE || len != be32_to_cpu(header->length))
        rc = -EFAULT;

    return rc ? rc : len;
}

/**
 * tpm_transmit - Internal kernel interface to transmit TPM commands.
 * @chip:    a TPM chip to use
 * @buf:    a TPM command buffer
 * @bufsiz:    length of the TPM command buffer
 *
 * A wrapper around tpm_try_transmit() that handles TPM2_RC_RETRY returns from
 * the TPM and retransmits the command after a delay up to a maximum wait of
 * TPM2_DURATION_LONG.
 *
 * Note that TPM 1.x never returns TPM2_RC_RETRY so the retry logic is TPM 2.0
 * only.
 *
 * Return:
 * * The response length    - OK
 * * -errno            - A system error
 */
ssize_t tpm_transmit(struct tpm_chip *chip, u8 *buf, size_t bufsiz)
{
    struct tpm_header *header = (struct tpm_header *)buf;
    /* space for header and handles */
    u8 save[TPM_HEADER_SIZE + 3*sizeof(u32)];
    unsigned int delay_msec = TPM2_DURATION_SHORT;
    u32 rc = 0;
    ssize_t ret;
    const size_t save_size = min(sizeof(save), bufsiz);
    /* the command code is where the return code will be */
    u32 cc = be32_to_cpu(header->return_code);

    /*
     * Subtlety here: if we have a space, the handles will be
     * transformed, so when we restore the header we also have to
     * restore the handles.
     */
    memcpy(save, buf, save_size);

    for (;;) {
        ret = tpm_try_transmit(chip, buf, bufsiz);
        if (ret < 0)
            break;
        rc = be32_to_cpu(header->return_code);
        if (rc != TPM2_RC_RETRY && rc != TPM2_RC_TESTING)
            break;
        /*
         * return immediately if self test returns test
         * still running to shorten boot time.
         */
        if (rc == TPM2_RC_TESTING && cc == TPM2_CC_SELF_TEST)
            break;

        if (delay_msec > TPM2_DURATION_LONG) {
            if (rc == TPM2_RC_RETRY)
                dev_err(&chip->dev, "in retry loop\n");
            else
                dev_err(&chip->dev, "self test is still running\n");
            break;
        }
        tpm_msleep(delay_msec);
        delay_msec *= 2;
        memcpy(buf, save, save_size);
    }
    return ret;
}

/**
 * tpm_transmit_cmd - send a tpm command to the device
 * @chip:            a TPM chip to use
 * @buf:            a TPM command buffer
 * @min_rsp_body_length:    minimum expected length of response body
 * @desc:            command description used in the error message
 *
 * Return:
 * * 0        - OK
 * * -errno    - A system error
 * * TPM_RC    - A TPM error
 */
ssize_t tpm_transmit_cmd(struct tpm_chip *chip, struct tpm_buf *buf,
             size_t min_rsp_body_length, const char *desc)
{
    const struct tpm_header *header = (struct tpm_header *)buf->data;
    int err;
    ssize_t len;

    len = tpm_transmit(chip, buf->data, PAGE_SIZE);
    if (len <  0)
        return len;

    err = be32_to_cpu(header->return_code);
    if (err != 0 && err != TPM_ERR_DISABLED && err != TPM_ERR_DEACTIVATED
        && err != TPM2_RC_TESTING && desc)
        dev_err(&chip->dev, "A TPM error (%d) occurred %s\n", err, desc);
    if (err)
        return err;

    if (len < min_rsp_body_length + TPM_HEADER_SIZE)
        return -EFAULT;

    return 0;
}

int tpm_auto_startup(struct tpm_chip *chip)
{
    int rc;

    if (!(chip->ops->flags & TPM_OPS_AUTO_STARTUP))
        return 0;

    rc = tpm2_auto_startup(chip);

    return rc;
}

/**
 * We are about to suspend. Save the TPM state
 * so that it can be restored.
 *
 * !!!A power cycle should happen next!!!
 *
 * tpm_chip_stop() -> to release locality
 */
int tpm_pm_suspend(struct device *dev)
{
    struct tpm_chip *chip = dev_get_drvdata(dev);
    int rc = 0;

    if (chip->flags & TPM_CHIP_FLAG_ALWAYS_POWERED)
        goto suspended;

    if (!tpm_chip_start(chip)) {
        if (chip->flags & TPM_CHIP_FLAG_TPM2)
            tpm2_shutdown(chip, TPM2_SU_STATE);
        tpm_chip_stop(chip);
    }

suspended:
    return rc;
}

/**
 * Resume from a power safe.
 *
 * tpm_chip_start() -> to request locality
 */
int tpm_pm_resume(struct device *dev)
{
#ifdef ORIGINAL_CODE
    struct tpm_chip *chip = dev_get_drvdata(dev);

    if (chip == NULL)
        return -ENODEV;

    return 0;
#else
    /**
     * Counterpart tpm_pm_suspend() will issue
     * tpm2_shutdown(TPM2_SU_STATE) and relinquish
     * locality; power down is expected to
     * happen next. After a power cycle,
     * tis has to issue tpm_chip_start() to request
     * for locality then tpm2_startup(TPM2_SU_STATE)
     */
    struct tpm_chip *chip = dev_get_drvdata(dev);
    int rc = 0;

    if (chip->flags & TPM_CHIP_FLAG_ALWAYS_POWERED)
        goto out;

    rc = tpm_chip_start(chip);
    if (rc)
        goto out;

    rc = tpm2_startup_st(chip);

out:
    return rc;
#endif
}

/**
 * tpm_get_random() - get random bytes from the TPM's RNG
 * @chip:    a &struct tpm_chip instance, %NULL for the default chip
 * @out:    destination buffer for the random bytes
 * @max:    the max number of bytes to write to @out
 *
 * Return: number of random bytes read or a negative error value.
 */
int tpm_get_random(struct tpm_chip *chip, u8 *out, size_t max)
{
    int rc = 0;

    if (!out || max > TPM_MAX_RNG_DATA)
        return -EINVAL;

    chip = tpm_find_get_ops(chip);
    if (!chip)
        return -ENODEV;

    if (chip->flags & TPM_CHIP_FLAG_TPM2)
        rc = tpm2_get_random(chip, out, max);

    tpm_put_ops(chip);
    return rc;
}

