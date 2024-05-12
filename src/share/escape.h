/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <uchar.h>

#include "string-util.h"
#include "missing.h"

/* What characters are special in the shell? */
/* must be escaped outside and inside double-quotes */
#define SHELL_NEED_ESCAPE "\"\\`$"
/* can be escaped or double-quoted */
#define SHELL_NEED_QUOTES SHELL_NEED_ESCAPE GLOB_CHARS "'()<>|&;"

typedef enum UnescapeFlags {
        UNESCAPE_RELAX = 1,
} UnescapeFlags;

int cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit);
