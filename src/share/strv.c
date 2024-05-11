/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fileio.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

char *strv_find(char **l, const char *name) {
        char **i;

        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

void strv_clear(char **l) {
        char **k;

        if (!l)
                return;

        for (k = l; *k; k++)
                free(*k);

        *l = NULL;
}

char **strv_free(char **l) {
        strv_clear(l);
        free(l);
        return NULL;
}

char **strv_free_erase(char **l) {
        char **i;

        STRV_FOREACH(i, l)
                string_erase(*i);

        return strv_free(l);
}

char **strv_copy(char * const *l) {
        char **r, **k;

        k = r = new(char*, strv_length(l) + 1);
        if (!r)
                return NULL;

        if (l)
                for (; *l; k++, l++) {
                        *k = strdup(*l);
                        if (!*k) {
                                strv_free(r);
                                return NULL;
                        }
                }

        *k = NULL;
        return r;
}

unsigned strv_length(char * const *l) {
        unsigned n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

char **strv_new_ap(const char *x, va_list ap) {
        const char *s;
        char **a;
        unsigned n = 0, i = 0;
        va_list aq;

        /* As a special trick we ignore all listed strings that equal
         * STRV_IGNORE. This is supposed to be used with the
         * STRV_IFNOTNULL() macro to include possibly NULL strings in
         * the string list. */

        if (x) {
                n = x == STRV_IGNORE ? 0 : 1;

                va_copy(aq, ap);
                while ((s = va_arg(aq, const char*))) {
                        if (s == STRV_IGNORE)
                                continue;

                        n++;
                }

                va_end(aq);
        }

        a = new(char*, n+1);
        if (!a)
                return NULL;

        if (x) {
                if (x != STRV_IGNORE) {
                        a[i] = strdup(x);
                        if (!a[i])
                                goto fail;
                        i++;
                }

                while ((s = va_arg(ap, const char*))) {

                        if (s == STRV_IGNORE)
                                continue;

                        a[i] = strdup(s);
                        if (!a[i])
                                goto fail;

                        i++;
                }
        }

        a[i] = NULL;

        return a;

fail:
        strv_free(a);
        return NULL;
}

char **strv_new(const char *x, ...) {
        char **r;
        va_list ap;

        va_start(ap, x);
        r = strv_new_ap(x, ap);
        va_end(ap);

        return r;
}

char **strv_split(const char *s, const char *separator) {
        const char *word, *state;
        size_t l;
        unsigned n, i;
        char **r;

        assert(s);

        n = 0;
        FOREACH_WORD_SEPARATOR(word, l, s, separator, state)
                n++;

        r = new(char*, n+1);
        if (!r)
                return NULL;

        i = 0;
        FOREACH_WORD_SEPARATOR(word, l, s, separator, state) {
                r[i] = strndup(word, l);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }

                i++;
        }

        r[i] = NULL;
        return r;
}

int strv_push(char ***l, char *value) {
        char **c;
        unsigned n, m;

        if (!value)
                return 0;

        n = strv_length(*l);

        /* Increase and check for overflow */
        m = n + 2;
        if (m < n)
                return -ENOMEM;

        c = realloc_multiply(*l, m, sizeof(char*));
        if (!c)
                return -ENOMEM;

        c[n] = value;
        c[n+1] = NULL;

        *l = c;
        return 0;
}

int strv_consume(char ***l, char *value) {
        int r;

        r = strv_push(l, value);
        if (r < 0)
                free(value);

        return r;
}

int strv_extend(char ***l, const char *value) {
        char *v;

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        return strv_consume(l, v);
}

char **strv_uniq(char **l) {
        char **i;

        /* Drops duplicate entries. The first identical string will be
         * kept, the others dropped */

        STRV_FOREACH(i, l)
                strv_remove(i+1, *i);

        return l;
}

char **strv_remove(char **l, const char *s) {
        char **f, **t;

        if (!l)
                return NULL;

        assert(s);

        /* Drops every occurrence of s in the string list, edits
         * in-place. */

        for (f = t = l; *f; f++)
                if (streq(*f, s))
                        free(*f);
                else
                        *(t++) = *f;

        *t = NULL;
        return l;
}

char **strv_split_nulstr(const char *s) {
        const char *i;
        char **r = NULL;

        NULSTR_FOREACH(i, s)
                if (strv_extend(&r, i) < 0) {
                        strv_free(r);
                        return NULL;
                }

        if (!r)
                return strv_new(NULL, NULL);

        return r;
}
