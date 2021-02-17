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

#include <linux/tpm.h>
#include "tis_adapt.h"

void usleep_range(unsigned long min, unsigned long max) {
    max /= 1000;
    if (max == 0)
        max = 1;
    cyhal_system_delay_ms(max);
}

void *safeAlloc(size_t size) {
    void *ptr = NULL;
    ptr = malloc(size);
    memset(ptr, 0, size);
    return ptr;
}

int tpm2_init_space(struct tpm_space *space, unsigned int buf_size) {

    // context_buf as constant ptr
    space->context_buf = malloc(buf_size);
    if (space->context_buf == NULL) {
        return -ENOMEM;
    }

    // session_buf as current position ptr
    space->session_buf = space->context_buf;

    // buf_size as total data received instead of
    // buffer capacity
    space->buf_size = 0;

    return 0;
}

void tpm2_del_space(struct tpm_chip *chip, struct tpm_space *space)
{
    (void)space;
    free(chip->work_space.context_buf);
}

