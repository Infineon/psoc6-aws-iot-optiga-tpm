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

#ifndef ADAPT_H_
#define ADAPT_H_
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <cy_retarget_io.h>
#include <cyhal.h>
#include <asm-generic/errno-tpm.h>

#define __LITTLE_ENDIAN__

/* ENDIANNESS */
#ifdef __LITTLE_ENDIAN__
#define cpu_to_be16(x) bswap_16(x)
#define be16_to_cpu(x) bswap_16(x)
#define cpu_to_be32(x) bswap_32(x)
#define be32_to_cpu(x) bswap_32(x)
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#else
#define cpu_to_be16(x) (x)
#define be16_to_cpu(x) (x)
#define cpu_to_be32(x) (x)
#define be32_to_cpu(x) (x)
#define cpu_to_le16(x) bswap_16(x)
#define le16_to_cpu(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#endif

#if MAXLOGLEVEL > 0
#define dev_dbg(a, ...) printf(__VA_ARGS__)
#define dev_warn(a, ...) printf(__VA_ARGS__)
#define dev_info(a, ...) printf(__VA_ARGS__)
#define dev_err(a, ...) printf(__VA_ARGS__)
#else
#define dev_dbg(a, ...)
#define dev_warn(a, ...)
#define dev_info(a, ...)
#define dev_err(a, ...)
#endif

#define WARN(a, b) printf(b)
#define container_of(ptr, type, member) ({              \
    void *__mptr = (void *)(ptr);                   \
    ((type *)(__mptr - offsetof(type, member))); })
#define __packed __attribute__((__packed__))
#define BIT(nr)            (1ul << (nr))
#define min_t(type, a, b)    ( ((type)(a) < (type)(b)) ? (type)(a) : (type)(b) )
#define max_t(type, a, b)    ( ((type)(a) > (type)(b)) ? (type)(a) : (type)(b) )
#define min(a, b) ( ((a) < (b)) ? (a) : (b) )
#define PAGE_SIZE    1024
#define __get_free_page(a) malloc(PAGE_SIZE)
#define free_page(a) free((u8 *)a)
#define kfree(a) free((u8 *)a)
#define devm_kzalloc(a,b,c) safeAlloc(b)
#define devm_kmalloc(a,b,c) safeAlloc(b)
#define kzalloc(a,b) safeAlloc(a)
#define msecs_to_jiffies
#define rmb()        __asm__ __volatile__ ("dsb" : : : "memory")
#define GFP_KERNEL
#define MAX_ERRNO   4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

typedef unsigned char        u8;
typedef unsigned short        u16;
typedef unsigned int        u32;
typedef signed char            s8;
typedef short                s16;
typedef int                    s32;
typedef u8  __u8;
typedef u16 __be16;
typedef u32 __be32;
typedef u16 __le16;
typedef u16 __be16;
typedef u32 __le32;
typedef u32 __be32;
typedef void *acpi_handle;
typedef void wait_queue_head_t;

static inline long PTR_ERR(const void *ptr)
{
    return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((unsigned long)ptr);
}

static inline void * ERR_PTR(long error_)
{
    return (void *) error_;
}

static inline u16 bswap_16(u16 value)
{
    return ((value & (0xff))      << 8) | \
           ((value & (0xff << 8)) >> 8);
}

static inline u32 bswap_32(u32 value)
{
    return ((value & (0xff))       << 24) | \
           ((value & (0xff << 8))  << 8)  | \
           ((value & (0xff << 16)) >> 8)  | \
           ((value & (0xff << 24)) >> 24);
}

void usleep_range(unsigned long min, unsigned long max);
void *safeAlloc(size_t size);

#endif
