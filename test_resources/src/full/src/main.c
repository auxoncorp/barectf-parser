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

#define BARECTF_BUF_SIZE (256)

static const char VERSION[] = "1.0.0";

static struct barectf_platform_linux_fs_ctx *g_platform_ctx;
static struct barectf_default_ctx *g_probe = NULL;

int main(int argc, char **argv)
{
    g_platform_ctx = barectf_platform_linux_fs_init(PLATFORM_CTX_DEFAULT, BARECTF_BUF_SIZE, TRACE_DIR "/stream");
    assert(g_platform_ctx != NULL);

    g_probe = barectf_platform_linux_fs_get_ctx(g_platform_ctx);
    assert(g_probe != NULL);

    barectf_default_trace_init(g_probe, 98, 1, VERSION);
    increment_clock(1);
    barectf_default_trace_foobar(g_probe, 97, 3, 21);
    increment_clock(1);
    barectf_default_trace_floats(g_probe, 96, 1.1, 2.2);
    increment_clock(1);
    barectf_default_trace_enums(g_probe, 95, 0, -1, 19, 200);

    uint16_t foo[4] = {1, 2, 3, 4};
    const char* bar[3] = {"b0", "b1", "b2"};
    increment_clock(1);
    barectf_default_trace_arrays(g_probe, 94, foo, 3, bar);

    increment_clock(1);
    barectf_default_trace_shutdown(g_probe, 93);

    barectf_platform_linux_fs_fini(g_platform_ctx);

    return EXIT_SUCCESS;
}
