#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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
