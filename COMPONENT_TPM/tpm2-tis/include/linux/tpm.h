/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004,2007,2008 IBM Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 * Debora Velarde <dvelarde@us.ibm.com>
 *
 * Maintained by: <tpmdd_devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 */
#ifndef __LINUX_TPM_H__
#define __LINUX_TPM_H__

#include <tis_adapt.h>
#include <linux/device.h>

struct tpm_chip;

#define TPM_HEADER_SIZE        10

enum tpm_chip_flags {
    TPM_CHIP_FLAG_TPM2        = BIT(1),
    //TPM_CHIP_FLAG_IRQ        = BIT(2),
    //TPM_CHIP_FLAG_VIRTUAL        = BIT(3),
    TPM_CHIP_FLAG_HAVE_TIMEOUTS    = BIT(4),
    TPM_CHIP_FLAG_ALWAYS_POWERED    = BIT(5),
    //TPM_CHIP_FLAG_FIRMWARE_POWER_MANAGED    = BIT(6),
};

struct tpm_header {
    __be16 tag;
    __be32 length;
    union {
        __be32 ordinal;
        __be32 return_code;
    };
} __packed;

/* A string buffer type for constructing TPM commands. This is based on the
 * ideas of string buffer code in security/keys/trusted.h but is heap based
 * in order to keep the stack usage minimal.
 */

enum tpm_buf_flags {
    TPM_BUF_OVERFLOW    = BIT(0),
};

struct tpm_buf {
    unsigned int flags;
    u8 *data;
};

enum TPM_OPS_FLAGS {
    TPM_OPS_AUTO_STARTUP = BIT(0),
};

struct tpm_class_ops {
    unsigned int flags;
    const u8 req_complete_mask;
    const u8 req_complete_val;
    bool (*req_canceled)(struct tpm_chip *chip, u8 status);
    int (*recv) (struct tpm_chip *chip, u8 *buf, size_t len);
    int (*send) (struct tpm_chip *chip, u8 *buf, size_t len);
    void (*cancel) (struct tpm_chip *chip);
    u8 (*status) (struct tpm_chip *chip);
    void (*update_timeouts)(struct tpm_chip *chip,
                unsigned long *timeout_cap);
    void (*update_durations)(struct tpm_chip *chip,
                 unsigned long *duration_cap);
    int (*go_idle)(struct tpm_chip *chip);
    int (*cmd_ready)(struct tpm_chip *chip);
    int (*request_locality)(struct tpm_chip *chip, int loc);
    int (*relinquish_locality)(struct tpm_chip *chip, int loc);
    void (*clk_enable)(struct tpm_chip *chip, bool value);
};

/* Indexes the duration array */
enum tpm_duration {
    TPM_SHORT = 0,
    TPM_MEDIUM = 1,
    TPM_LONG = 2,
    TPM_LONG_LONG = 3,
    TPM_UNDEFINED,
    TPM_NUM_DURATIONS = TPM_UNDEFINED,
};

struct tpm_space {
    u8 *context_buf;
    u8 *session_buf;
    u32 buf_size;
};

struct tpm_chip {
    struct device dev;
    const struct tpm_class_ops *ops;
    unsigned int flags;

    unsigned long duration[TPM_NUM_DURATIONS];

    unsigned long timeout_a;
    unsigned long timeout_b;
    unsigned long timeout_c;
    unsigned long timeout_d;

    struct tpm_space work_space;

    /* active locality */
    int locality;
};

enum tpm2_timeouts {
    TPM2_TIMEOUT_A          =    750,
    TPM2_TIMEOUT_B          =   2000,
    TPM2_TIMEOUT_C          =    200,
    TPM2_TIMEOUT_D          =     30,
    TPM2_DURATION_SHORT     =     20,
    TPM2_DURATION_MEDIUM    =    750,
    TPM2_DURATION_LONG      =   2000,
    TPM2_DURATION_LONG_LONG = 300000,
    TPM2_DURATION_DEFAULT   = 120000,
};

enum tpm2_structures {
    TPM2_ST_NO_SESSIONS    = 0x8001,
    TPM2_ST_SESSIONS    = 0x8002,
};

enum tpm2_return_codes {
    TPM2_RC_SUCCESS        = 0x0000,
    TPM2_RC_HASH        = 0x0083, /* RC_FMT1 */
    TPM2_RC_HANDLE        = 0x008B,
    TPM2_RC_INITIALIZE    = 0x0100, /* RC_VER1 */
    TPM2_RC_FAILURE        = 0x0101,
    TPM2_RC_DISABLED    = 0x0120,
    TPM2_RC_COMMAND_CODE    = 0x0143,
    TPM2_RC_TESTING        = 0x090A, /* RC_WARN */
    TPM2_RC_REFERENCE_H0    = 0x0910,
    TPM2_RC_RETRY        = 0x0922,
};

enum tpm2_command_codes {
    TPM2_CC_FIRST                = 0x011F,
    TPM2_CC_HIERARCHY_CONTROL       = 0x0121,
    TPM2_CC_HIERARCHY_CHANGE_AUTH   = 0x0129,
    TPM2_CC_CREATE_PRIMARY          = 0x0131,
    TPM2_CC_SEQUENCE_COMPLETE       = 0x013E,
    TPM2_CC_SELF_TEST            = 0x0143,
    TPM2_CC_STARTUP                = 0x0144,
    TPM2_CC_SHUTDOWN            = 0x0145,
    TPM2_CC_NV_READ                 = 0x014E,
    TPM2_CC_CREATE                = 0x0153,
    TPM2_CC_LOAD                = 0x0157,
    TPM2_CC_SEQUENCE_UPDATE         = 0x015C,
    TPM2_CC_UNSEAL                = 0x015E,
    TPM2_CC_CONTEXT_LOAD            = 0x0161,
    TPM2_CC_CONTEXT_SAVE            = 0x0162,
    TPM2_CC_FLUSH_CONTEXT            = 0x0165,
    TPM2_CC_VERIFY_SIGNATURE        = 0x0177,
    TPM2_CC_GET_CAPABILITY            = 0x017A,
    TPM2_CC_GET_RANDOM            = 0x017B,
    TPM2_CC_PCR_READ            = 0x017E,
    TPM2_CC_PCR_EXTEND            = 0x0182,
    TPM2_CC_EVENT_SEQUENCE_COMPLETE = 0x0185,
    TPM2_CC_HASH_SEQUENCE_START     = 0x0186,
    TPM2_CC_CREATE_LOADED           = 0x0191,
    TPM2_CC_LAST                = 0x0193, /* Spec 1.36 */
};

enum tpm2_capabilities {
    TPM2_CAP_HANDLES    = 1,
    TPM2_CAP_COMMANDS    = 2,
    TPM2_CAP_PCRS        = 5,
    TPM2_CAP_TPM_PROPERTIES = 6,
};

enum tpm2_properties {
    TPM_PT_TOTAL_COMMANDS    = 0x0129,
};

enum tpm2_startup_types {
    TPM2_SU_CLEAR    = 0x0000,
    TPM2_SU_STATE    = 0x0001,
};

static inline void tpm_buf_reset(struct tpm_buf *buf, u16 tag, u32 ordinal)
{
    struct tpm_header *head = (struct tpm_header *)buf->data;

    head->tag = cpu_to_be16(tag);
    head->length = cpu_to_be32(sizeof(*head));
    head->ordinal = cpu_to_be32(ordinal);
}

static inline int tpm_buf_init(struct tpm_buf *buf, u16 tag, u32 ordinal)
{
    buf->data = (u8 *)__get_free_page(GFP_KERNEL);
    if (!buf->data)
        return -ENOMEM;

    buf->flags = 0;
    tpm_buf_reset(buf, tag, ordinal);
    return 0;
}

static inline void tpm_buf_destroy(struct tpm_buf *buf)
{
    free_page((unsigned long)buf->data);
}

static inline u32 tpm_buf_length(struct tpm_buf *buf)
{
    struct tpm_header *head = (struct tpm_header *)buf->data;

    return be32_to_cpu(head->length);
}

static inline void tpm_buf_append(struct tpm_buf *buf,
                  const unsigned char *new_data,
                  unsigned int new_len)
{
    struct tpm_header *head = (struct tpm_header *)buf->data;
    u32 len = tpm_buf_length(buf);

    /* Return silently if overflow has already happened. */
    if (buf->flags & TPM_BUF_OVERFLOW)
        return;

    if ((len + new_len) > PAGE_SIZE) {
        WARN(1, "tpm_buf: overflow\n");
        buf->flags |= TPM_BUF_OVERFLOW;
        return;
    }

    memcpy(&buf->data[len], new_data, new_len);
    head->length = cpu_to_be32(len + new_len);
}

static inline void tpm_buf_append_u8(struct tpm_buf *buf, const u8 value)
{
    tpm_buf_append(buf, &value, 1);
}

static inline void tpm_buf_append_u16(struct tpm_buf *buf, const u16 value)
{
    __be16 value2 = cpu_to_be16(value);

    tpm_buf_append(buf, (u8 *) &value2, 2);
}

static inline void tpm_buf_append_u32(struct tpm_buf *buf, const u32 value)
{
    __be32 value2 = cpu_to_be32(value);

    tpm_buf_append(buf, (u8 *) &value2, 4);
}

#endif
