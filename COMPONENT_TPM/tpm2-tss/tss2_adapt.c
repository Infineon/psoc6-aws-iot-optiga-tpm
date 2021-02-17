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

#include <tss2/tss2_tctildr.h>

void
Tss2_TctiLdr_Finalize (TSS2_TCTI_CONTEXT **context) {
    (void)context;
}

TSS2_RC
Tss2_TctiLdr_Initialize_Ex (const char *name,
                            const char *conf,
                            TSS2_TCTI_CONTEXT **context) {
    (void)name;
    (void)conf;
    (void)context;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
Tss2_TctiLdr_Initialize (const char *nameConf,
                         TSS2_TCTI_CONTEXT **context) {
    (void)nameConf;
    (void)context;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
Tss2_TctiLdr_GetInfo (const char *name,
                      TSS2_TCTI_INFO **info) {
    (void)name;
    (void)info;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

void
Tss2_TctiLdr_FreeInfo (TSS2_TCTI_INFO **info) {
    (void)info;
}

