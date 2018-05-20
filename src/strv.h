/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <fnmatch.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "macro.h"
#include "util.h"

char *strv_find(char **l, const char *name) _pure_;
char *strv_find_prefix(char **l, const char *name) _pure_;

char **strv_free(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char**, strv_free);
#define _cleanup_strv_free_ _cleanup_(strv_freep)

char **strv_free_erase(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char**, strv_free_erase);
#define _cleanup_strv_free_erase_ _cleanup_(strv_free_erasep)

void strv_clear(char **l);

char **strv_copy(char * const *l);
unsigned strv_length(char * const *l) _pure_;

int strv_extend(char ***l, const char *value);
int strv_push(char ***l, char *value);
int strv_consume(char ***l, char *value);

char **strv_remove(char **l, const char *s);
char **strv_uniq(char **l);

#define strv_contains(l, s) (!!strv_find((l), (s)))

char **strv_new(const char *x, ...) _sentinel_;
char **strv_new_ap(const char *x, va_list ap);

#define STRV_IGNORE ((const char *) -1)

static inline const char* STRV_IFNOTNULL(const char *x) {
        return x ? x : STRV_IGNORE;
}

static inline bool strv_isempty(char * const *l) {
        return !l || !*l;
}

char **strv_split(const char *s, const char *separator);

char **strv_split_nulstr(const char *s);

#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)

#define STRV_FOREACH_BACKWARDS(s, l)            \
        STRV_FOREACH(s, l)                      \
                ;                               \
        for ((s)--; (l) && ((s) >= (l)); (s)--)

#define STRV_FOREACH_PAIR(x, y, l)               \
        for ((x) = (l), (y) = (x+1); (x) && *(x) && *(y); (x) += 2, (y) = (x + 1))

#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))

#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)
