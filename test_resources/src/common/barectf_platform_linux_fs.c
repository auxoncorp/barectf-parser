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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

#include "barectf_platform_linux_fs.h"
#include "barectf.h"

#ifdef __cplusplus
# define _FROM_VOID_PTR(_type, _value)	static_cast<_type *>(_value)
#else
# define _FROM_VOID_PTR(_type, _value)	((_type *) (_value))
#endif

#if defined(TRACE_CFG_PACKET_CONTEXT_FIELD)
    #define bctf_open_packet(ctx, pctx) TRACE_CAT3(barectf_, TRACE_CFG_STREAM_TYPE, _open_packet)(ctx, pctx)
#else
    #define bctf_open_packet(ctx) TRACE_CAT3(barectf_, TRACE_CFG_STREAM_TYPE, _open_packet)(ctx)
#endif
#define bctf_close_packet(ctx) TRACE_CAT3(barectf_, TRACE_CFG_STREAM_TYPE, _close_packet)(ctx)

struct barectf_platform_linux_fs_ctx {
    barectf_platform_ctx_kind ctx_tag;
    struct TRACE_CAT3(barectf_, TRACE_CFG_STREAM_TYPE, _ctx) default_ctx;
	FILE *fh;
};

static uint64_t g_clock = 0;

void increment_clock(const uint64_t dt)
{
    g_clock += dt;
}

static uint64_t get_clock(void * const data)
{
    (void) data;
    return g_clock;
}

static void * get_ctx(struct barectf_platform_linux_fs_ctx * const platform_ctx)
{
    if(platform_ctx->ctx_tag == PLATFORM_CTX_DEFAULT)
    {
        return (void*) &platform_ctx->default_ctx;
    }
    else
    {
        assert(0);
        return NULL;
    }
}


static void write_packet(const struct barectf_platform_linux_fs_ctx * const platform_ctx)
{
	const size_t nmemb = fwrite(
            barectf_packet_buf(get_ctx((struct barectf_platform_linux_fs_ctx *) platform_ctx)),
	        barectf_packet_buf_size(get_ctx((struct barectf_platform_linux_fs_ctx *) platform_ctx)),
            1,
            platform_ctx->fh);

	assert(nmemb == 1);
}

static int is_backend_full(void * const data)
{
	int is_backend_full = 0;
	return is_backend_full;
}

static void open_packet(void * const data)
{
	struct barectf_platform_linux_fs_ctx * const platform_ctx =
		_FROM_VOID_PTR(struct barectf_platform_linux_fs_ctx, data);

    if(platform_ctx->ctx_tag == PLATFORM_CTX_DEFAULT)
    {
#if defined(TRACE_CFG_PACKET_CONTEXT_FIELD)
        bctf_open_packet(&platform_ctx->default_ctx, TRACE_CFG_PACKET_CONTEXT_FIELD);
#else
        bctf_open_packet(&platform_ctx->default_ctx);
#endif
    }
    else
    {
        assert(0);
    }
}

static void close_packet(void * const data)
{
	struct barectf_platform_linux_fs_ctx * const platform_ctx =
		_FROM_VOID_PTR(struct barectf_platform_linux_fs_ctx, data);

	/* Close packet now */
    if(platform_ctx->ctx_tag == PLATFORM_CTX_DEFAULT)
    {
        bctf_close_packet(&platform_ctx->default_ctx);
    }
    else
    {
        assert(0);
    }

	/* Write packet to file */
	write_packet(platform_ctx);
}

struct barectf_platform_linux_fs_ctx *barectf_platform_linux_fs_init(
        barectf_platform_ctx_kind kind,
	const unsigned int buf_size, const char * const data_stream_file_path)
{
	uint8_t *buf = NULL;
	struct barectf_platform_linux_fs_ctx *platform_ctx;

    struct barectf_platform_callbacks cbs =
    {
        .TRACE_CAT3(TRACE_CFG_CLOCK_TYPE, _clock_, get_value) = get_clock,
        .is_backend_full = is_backend_full,
        .open_packet = open_packet,
        .close_packet = close_packet,
    };

	platform_ctx = _FROM_VOID_PTR(struct barectf_platform_linux_fs_ctx,
		malloc(sizeof(*platform_ctx)));

	if (!platform_ctx) {
		goto error;
	}
    platform_ctx->ctx_tag = kind;

	buf = _FROM_VOID_PTR(uint8_t, malloc(buf_size));

	if (!buf) {
		goto error;
	}

	platform_ctx->fh = fopen(data_stream_file_path, "wb");

	if (!platform_ctx->fh) {
		goto error;
	}

	barectf_init(get_ctx(platform_ctx), buf, buf_size, cbs, platform_ctx);
	open_packet(platform_ctx);
	goto end;

error:
	free(platform_ctx);
	free(buf);

end:
	return platform_ctx;
}

void barectf_platform_linux_fs_fini(struct barectf_platform_linux_fs_ctx * const platform_ctx)
{
	if (barectf_packet_is_open(get_ctx(platform_ctx)) &&
			!barectf_packet_is_empty(get_ctx(platform_ctx))) {
		close_packet(platform_ctx);
	}

	fclose(platform_ctx->fh);
	free(barectf_packet_buf(get_ctx(platform_ctx)));
	free(platform_ctx);
}

struct TRACE_CAT3(barectf_, TRACE_CFG_STREAM_TYPE, _ctx) *barectf_platform_linux_fs_get_ctx(
    struct barectf_platform_linux_fs_ctx * const platform_ctx)
{
    if(platform_ctx->ctx_tag == PLATFORM_CTX_DEFAULT)
    {
        return &platform_ctx->default_ctx;
    }
    else
    {
        assert(0);
        return NULL;
    }
}
