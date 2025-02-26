#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include "barectf_platform_linux_fs.h"
#include "barectf.h"

#define BARECTF_BUF_SIZE (512)

static const char VERSION[] = "1.0.0";

static struct barectf_platform_linux_fs_ctx *g_platform_ctx;
static struct barectf_stream_a_ctx *g_probe = NULL;

int main(int argc, char **argv)
{
    g_platform_ctx = barectf_platform_linux_fs_init(PLATFORM_CTX_DEFAULT, BARECTF_BUF_SIZE, TRACE_DIR "/stream");
    assert(g_platform_ctx != NULL);

    g_probe = barectf_platform_linux_fs_get_ctx(g_platform_ctx);
    assert(g_probe != NULL);

    barectf_stream_a_trace_init(g_probe);

    increment_clock(1);
    barectf_stream_a_trace_shutdown(g_probe);

    barectf_platform_linux_fs_fini(g_platform_ctx);

    return EXIT_SUCCESS;
}
