// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2004 IBM Corporation
 * Copyright (C) 2014 Intel Corporation
 *
 * Authors:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * Maintained by: <tpmdd-devel@lists.sourceforge.net>
 *
 * TPM chip management routines.
 */

#include "tpm.h"

struct tpm_chip tpm_tis_chip;

static int tpm_request_locality(struct tpm_chip *chip)
{
    int rc;

    if (!chip->ops->request_locality)
        return 0;

    rc = chip->ops->request_locality(chip, 0);
    if (rc < 0)
        return rc;

    chip->locality = rc;
    return 0;
}

static void tpm_relinquish_locality(struct tpm_chip *chip)
{
    int rc;

    if (!chip->ops->relinquish_locality)
            return;

    rc = chip->ops->relinquish_locality(chip, chip->locality);
    if (rc)
        dev_err(&chip->dev, "%s: : error %d\n", __func__, rc);

    chip->locality = -1;
}

static int tpm_cmd_ready(struct tpm_chip *chip)
{
    if (!chip->ops->cmd_ready)
        return 0;

    return chip->ops->cmd_ready(chip);
}

static int tpm_go_idle(struct tpm_chip *chip)
{
    if (!chip->ops->go_idle)
        return 0;

    return chip->ops->go_idle(chip);
}

static void tpm_clk_enable(struct tpm_chip *chip)
{
    if (chip->ops->clk_enable)
        chip->ops->clk_enable(chip, true);
}

static void tpm_clk_disable(struct tpm_chip *chip)
{
    if (chip->ops->clk_enable)
        chip->ops->clk_enable(chip, false);
}

/**
 * tpm_chip_start() - power on the TPM
 * @chip:    a TPM chip to use
 *
 * Return:
 * * The response length    - OK
 * * -errno            - A system error
 */
int tpm_chip_start(struct tpm_chip *chip)
{
    int ret;

    tpm_clk_enable(chip);

    if (chip->locality == -1) {
        ret = tpm_request_locality(chip);
        if (ret) {
            tpm_clk_disable(chip);
            return ret;
        }
    }

    ret = tpm_cmd_ready(chip);
    if (ret) {
        tpm_relinquish_locality(chip);
        tpm_clk_disable(chip);
        return ret;
    }

    return 0;
}

/**
 * tpm_chip_stop() - power off the TPM
 * @chip:    a TPM chip to use
 *
 * Return:
 * * The response length    - OK
 * * -errno            - A system error
 */
void tpm_chip_stop(struct tpm_chip *chip)
{
    tpm_go_idle(chip);
    tpm_relinquish_locality(chip);
    tpm_clk_disable(chip);
}

/**
 * tpm_try_get_ops() - Get a ref to the tpm_chip
 * @chip: Chip to ref
 *
 * The caller must already have some kind of locking to ensure that chip is
 * valid. This function will lock the chip so that the ops member can be
 * accessed safely. The locking prevents tpm_chip_unregister from
 * completing, so it should not be held for long periods.
 *
 * Returns -ERRNO if the chip could not be got.
 */
int tpm_try_get_ops(struct tpm_chip *chip)
{
    int rc = -EIO;

    if (!chip->ops)
        goto out_ops;

    rc = tpm_chip_start(chip);
    if (rc)
        goto out_lock;

    return 0;
out_lock:
out_ops:
    return rc;
}

/**
 * tpm_put_ops() - Release a ref to the tpm_chip
 * @chip: Chip to put
 *
 * This is the opposite pair to tpm_try_get_ops(). After this returns chip may
 * be kfree'd.
 */
void tpm_put_ops(struct tpm_chip *chip)
{
    tpm_chip_stop(chip);
}

/**
 * tpm_default_chip() - find a TPM chip and get a reference to it
 */
struct tpm_chip *tpm_default_chip(void)
{
    /* Should never reach here */
    return (struct tpm_chip *)NULL;
}

/**
 * tpm_find_get_ops() - find and reserve a TPM chip
 * @chip:    a &struct tpm_chip instance, %NULL for the default chip
 *
 * Finds a TPM chip and reserves its class device and operations. The chip must
 * be released with tpm_put_ops() after use.
 * This function is for internal use only. It supports existing TPM callers
 * by accepting NULL, but those callers should be converted to pass in a chip
 * directly.
 *
 * Return:
 * A reserved &struct tpm_chip instance.
 * %NULL if a chip is not found.
 * %NULL if the chip is not available.
 */
struct tpm_chip *tpm_find_get_ops(struct tpm_chip *chip)
{
    int rc;

    if (chip) {
        if (!tpm_try_get_ops(chip))
            return chip;
        return NULL;
    }

    chip = tpm_default_chip();
    if (!chip)
        return NULL;
    rc = tpm_try_get_ops(chip);

    if (rc)
        return NULL;
    return chip;
}

/**
 * tpm_dev_release() - free chip memory and the device number
 * @dev: the character device for the TPM chip
 *
 * This is used as the release function for the character device.
 */
static void tpm_dev_release(struct device *dev)
{
    struct tpm_chip *chip = container_of(dev, struct tpm_chip, dev);

    kfree(chip);
}

/**
 * tpm_chip_alloc() - allocate a new struct tpm_chip instance
 * @pdev: device to which the chip is associated
 *        At this point pdev mst be initialized, but does not have to
 *        be registered
 * @ops: struct tpm_class_ops instance
 *
 * Allocates a new struct tpm_chip instance and assigns a free
 * device number for it. Must be paired with put_device(&chip->dev).
 */
struct tpm_chip *tpm_chip_alloc(struct device *pdev,
                const struct tpm_class_ops *ops)
{
    struct tpm_chip *chip;
    int rc;

    chip = kzalloc(sizeof(*chip), GFP_KERNEL);
    if (chip == NULL)
        return ERR_PTR(-ENOMEM);

    chip->ops = ops;

    chip->dev.release = tpm_dev_release;
    chip->dev.parent = pdev;

    rc = tpm2_init_space(&chip->work_space, TPM_BUFSIZE); //TPM2_SPACE_BUFFER_SIZE);
    if (rc) {
        rc = -ENOMEM;
        goto out;
    }

    chip->locality = -1;
    return chip;

out:
    return ERR_PTR(rc);
}

/**
 * tpmm_chip_alloc() - allocate a new struct tpm_chip instance
 * @pdev: parent device to which the chip is associated
 * @ops: struct tpm_class_ops instance
 *
 * Same as tpm_chip_alloc except devm is used to do the put_device
 */
struct tpm_chip *tpmm_chip_alloc(struct device *pdev,
                 const struct tpm_class_ops *ops)
{
    struct tpm_chip *chip;

    chip = tpm_chip_alloc(pdev, ops);
    if (IS_ERR(chip))
        return chip;

    dev_set_drvdata(pdev, chip);

    return chip;
}

static int tpm_get_pcr_allocation(struct tpm_chip *chip)
{
    int rc;

    rc = tpm2_get_pcr_allocation(chip);

    if (rc > 0)
        return -ENODEV;

    return rc;
}

/*
 * tpm_chip_register() - create a character device for the TPM chip
 * @chip: TPM chip to use.
 *
 * Creates a character device for the TPM chip and adds sysfs attributes for
 * the device. As the last step this function adds the chip to the list of TPM
 * chips available for in-kernel use.
 *
 * This function should be only called after the chip initialization is
 * complete.
 */
int tpm_chip_register(struct tpm_chip *chip)
{
    int rc;

    rc = tpm_chip_start(chip);
    if (rc)
        return rc;
    rc = tpm_auto_startup(chip);
    if (rc) {
        tpm_chip_stop(chip);
        return rc;
    }

    rc = tpm_get_pcr_allocation(chip);
    tpm_chip_stop(chip);
    if (rc)
        return rc;

    return rc;
}

/*
 * tpm_chip_unregister() - release the TPM driver
 * @chip: TPM chip to use.
 *
 * Takes the chip first away from the list of available TPM chips and then
 * cleans up all the resources reserved by tpm_chip_register().
 *
 * Once this function returns the driver call backs in 'op's will not be
 * running and will no longer start.
 *
 * NOTE: This function should be only called before deinitializing chip
 * resources.
 */
void tpm_chip_unregister(struct tpm_chip *chip)
{
    (void)chip;
    // nothing relevant
}

