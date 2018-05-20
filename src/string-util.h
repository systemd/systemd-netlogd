/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <alloca.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "macro.h"

/* What is interpreted as whitespace? */
#define WHITESPACE        " \t\n\r"
#define NEWLINE           "\n\r"
#define QUOTES            "\"\'"
#define COMMENTS          "#;"
#define GLOB_CHARS        "*?["
#define DIGITS            "0123456789"
#define LOWERCASE_LETTERS "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS           LOWERCASE_LETTERS UPPERCASE_LETTERS
#define ALPHANUMERICAL    LETTERS DIGITS
#define HEXDIGITS         DIGITS "abcdefABCDEF"

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)

int strcmp_ptr(const char *a, const char *b) _pure_;

static inline bool streq_ptr(const char *a, const char *b) {
        return strcmp_ptr(a, b) == 0;
}

static inline const char* strempty(const char *s) {
        return s ? s : "";
}

static inline const char* strnull(const char *s) {
        return s ? s : "(null)";
}

static inline const char *strna(const char *s) {
        return s ? s : "n/a";
}

static inline bool isempty(const char *p) {
        return !p || !p[0];
}

static inline const char *empty_to_null(const char *p) {
        return isempty(p) ? NULL : p;
}

static inline char *startswith(const char *s, const char *prefix) {
        size_t l;

        l = strlen(prefix);
        if (strncmp(s, prefix, l) == 0)
                return (char*) s + l;

        return NULL;
}

static inline char *startswith_no_case(const char *s, const char *prefix) {
        size_t l;

        l = strlen(prefix);
        if (strncasecmp(s, prefix, l) == 0)
                return (char*) s + l;

        return NULL;
}

char *endswith(const char *s, const char *postfix) _pure_;
char *endswith_no_case(const char *s, const char *postfix) _pure_;

char *first_word(const char *s, const char *word) _pure_;

const char* split(const char **state, size_t *l, const char *separator, bool quoted);

#define FOREACH_WORD(word, length, s, state)                            \
        _FOREACH_WORD(word, length, s, WHITESPACE, false, state)

#define FOREACH_WORD_SEPARATOR(word, length, s, separator, state)       \
        _FOREACH_WORD(word, length, s, separator, false, state)

#define FOREACH_WORD_QUOTED(word, length, s, state)                     \
        _FOREACH_WORD(word, length, s, WHITESPACE, true, state)

#define _FOREACH_WORD(word, length, s, separator, quoted, state)        \
        for ((state) = (s), (word) = split(&(state), &(length), (separator), (quoted)); (word); (word) = split(&(state), &(length), (separator), (quoted)))

char *strappend(const char *s, const char *suffix);
char *strnappend(const char *s, const char *suffix, size_t length);

char *strjoin(const char *x, ...) _sentinel_;

#define strjoina(a, ...)                                                \
        ({                                                              \
                const char *_appendees_[] = { a, __VA_ARGS__ };         \
                char *_d_, *_p_;                                        \
                int _len_ = 0;                                          \
                unsigned _i_;                                           \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _len_ += strlen(_appendees_[_i_]);              \
                _p_ = _d_ = alloca(_len_ + 1);                          \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _p_ = stpcpy(_p_, _appendees_[_i_]);            \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })

char *strstrip(char *s);
char *truncate_nl(char *s);

char ascii_tolower(char x);

bool nulstr_contains(const char*nulstr, const char *needle);

void* memory_erase(void *p, size_t l);
char *string_erase(char *x);

char *string_free_erase(char *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(char *, string_free_erase);
#define _cleanup_string_free_erase_ _cleanup_(string_free_erasep)
