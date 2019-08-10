/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

typedef enum ExtractFlags {
        EXTRACT_RELAX                    = 1,
        EXTRACT_CUNESCAPE                = 2,
        EXTRACT_CUNESCAPE_RELAX          = 4,
        EXTRACT_QUOTES                   = 8,
        EXTRACT_DONT_COALESCE_SEPARATORS = 16,
        EXTRACT_RETAIN_ESCAPE            = 32,
} ExtractFlags;

int extract_first_word(const char **p, char **ret, const char *separators, ExtractFlags flags);
