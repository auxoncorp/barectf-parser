#ifndef _BARECTF_PLATFORM_LINUX_FS_H
#define _BARECTF_PLATFORM_LINUX_FS_H

/*
 * Copyright (c) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015-2020 Philippe Proulx <pproulx@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TRACE__CAT3(a, b, c) a##b##c
#define TRACE_CAT3(a, b, c) TRACE__CAT3(a, b, c)

#ifndef TRACE_CFG_STREAM_TYPE
#error "Missing TRACE_CFG_STREAM_TYPE"
#endif

#ifndef TRACE_CFG_CLOCK_TYPE
#error "Missing TRACE_CFG_CLOCK_TYPE"
#endif

typedef enum
{
    PLATFORM_CTX_DEFAULT = 0,
} barectf_platform_ctx_kind;

struct barectf_platform_linux_fs_ctx;

struct barectf_platform_linux_fs_ctx *barectf_platform_linux_fs_init(
    barectf_platform_ctx_kind kind,
	unsigned int buf_size, const char *data_stream_file_path);

void barectf_platform_linux_fs_fini(struct barectf_platform_linux_fs_ctx *ctx);

struct TRACE_CAT3(barectf_, TRACE_CFG_STREAM_TYPE, _ctx) *barectf_platform_linux_fs_get_ctx(
    struct barectf_platform_linux_fs_ctx * const platform_ctx);

void increment_clock(const uint64_t dt);

#ifdef __cplusplus
}
#endif

#endif /* _BARECTF_PLATFORM_LINUX_FS_H */
