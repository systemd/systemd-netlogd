/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

typedef enum {
        WRITE_STRING_FILE_CREATE = 1,
        WRITE_STRING_FILE_ATOMIC = 2,
        WRITE_STRING_FILE_AVOID_NEWLINE = 4,
        WRITE_STRING_FILE_VERIFY_ON_FAILURE = 8,
} WriteStringFileFlags;

int write_string_stream(FILE *f, const char *line, bool enforce_newline);

int read_one_line_file(const char *fn, char **line);
int read_full_file(const char *fn, char **contents, size_t *size);
int read_full_stream(FILE *f, char **contents, size_t *size);

int verify_file(const char *fn, const char *blob, bool accept_extra_nl);

int parse_env_file(const char *fname, const char *separator, ...) _sentinel_;

#define FOREACH_LINE(line, f, on_error)                         \
        for (;;)                                                \
                if (!fgets(line, sizeof(line), f)) {            \
                        if (ferror(f)) {                        \
                                on_error;                       \
                        }                                       \
                        break;                                  \
                } else

int fflush_and_check(FILE *f);

int fopen_temporary(const char *path, FILE **_f, char **_temp_path);
int mkostemp_safe(char *pattern, int flags);

int tempfn_xxxxxx(const char *p, const char *extra, char **ret);
