/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "utf8.h"

int extract_first_word(const char **p, char **ret, const char *separators, ExtractFlags flags) {
        _cleanup_free_ char *s = NULL;
        size_t allocated = 0, sz = 0;
        char c;
        int r;

        char quote = 0;                 /* 0 or ' or " */
        bool backslash = false;         /* whether we've just seen a backslash */

        assert(p);
        assert(ret);

        /* Bail early if called after last value or with no input */
        if (!*p)
                goto finish_force_terminate;
        c = **p;

        if (!separators)
                separators = WHITESPACE;

        /* Parses the first word of a string, and returns it in
         * *ret. Removes all quotes in the process. When parsing fails
         * (because of an uneven number of quotes or similar), leaves
         * the pointer *p at the first invalid character. */

        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS)
                if (!GREEDY_REALLOC(s, allocated, sz+1))
                        return -ENOMEM;

        for (;; (*p)++, c = **p) {
                if (c == 0)
                        goto finish_force_terminate;
                else if (strchr(separators, c)) {
                        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
                                (*p)++;
                                goto finish_force_next;
                        }
                } else {
                        /* We found a non-blank character, so we will always
                         * want to return a string (even if it is empty),
                         * allocate it here. */
                        if (!GREEDY_REALLOC(s, allocated, sz+1))
                                return -ENOMEM;
                        break;
                }
        }

        for (;; (*p)++, c = **p) {
                if (backslash) {
                        if (!GREEDY_REALLOC(s, allocated, sz+7))
                                return -ENOMEM;

                        if (c == 0) {
                                if ((flags & EXTRACT_CUNESCAPE_RELAX) &&
                                    (!quote || flags & EXTRACT_RELAX)) {
                                        /* If we find an unquoted trailing backslash and we're in
                                         * EXTRACT_CUNESCAPE_RELAX mode, keep it verbatim in the
                                         * output.
                                         *
                                         * Unbalanced quotes will only be allowed in EXTRACT_RELAX
                                         * mode, EXTRACT_CUNESCAPE_RELAX mode does not allow them.
                                         */
                                        s[sz++] = '\\';
                                        goto finish_force_terminate;
                                }
                                if (flags & EXTRACT_RELAX)
                                        goto finish_force_terminate;
                                return -EINVAL;
                        }

                        if (flags & EXTRACT_CUNESCAPE) {
                                bool eight_bit = false;
                                char32_t u;

                                r = cunescape_one(*p, (size_t) -1, &u, &eight_bit);
                                if (r < 0) {
                                        if (flags & EXTRACT_CUNESCAPE_RELAX) {
                                                s[sz++] = '\\';
                                                s[sz++] = c;
                                        } else
                                                return -EINVAL;
                                } else {
                                        (*p) += r - 1;

                                        if (eight_bit)
                                                s[sz++] = u;
                                        else
                                                sz += utf8_encode_unichar(s + sz, u);
                                }
                        } else
                                s[sz++] = c;

                        backslash = false;

                } else if (quote) {     /* inside either single or double quotes */
                        for (;; (*p)++, c = **p) {
                                if (c == 0) {
                                        if (flags & EXTRACT_RELAX)
                                                goto finish_force_terminate;
                                        return -EINVAL;
                                } else if (c == quote) {        /* found the end quote */
                                        quote = 0;
                                        break;
                                } else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
                                        backslash = true;
                                        break;
                                } else {
                                        if (!GREEDY_REALLOC(s, allocated, sz+2))
                                                return -ENOMEM;

                                        s[sz++] = c;
                                }
                        }

                } else {
                        for (;; (*p)++, c = **p) {
                                if (c == 0)
                                        goto finish_force_terminate;
                                else if ((c == '\'' || c == '"') && (flags & EXTRACT_QUOTES)) {
                                        quote = c;
                                        break;
                                } else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
                                        backslash = true;
                                        break;
                                } else if (strchr(separators, c)) {
                                        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
                                                (*p)++;
                                                goto finish_force_next;
                                        }
                                        /* Skip additional coalesced separators. */
                                        for (;; (*p)++, c = **p) {
                                                if (c == 0)
                                                        goto finish_force_terminate;
                                                if (!strchr(separators, c))
                                                        break;
                                        }
                                        goto finish;

                                } else {
                                        if (!GREEDY_REALLOC(s, allocated, sz+2))
                                                return -ENOMEM;

                                        s[sz++] = c;
                                }
                        }
                }
        }

finish_force_terminate:
        *p = NULL;
finish:
        if (!s) {
                *p = NULL;
                *ret = NULL;
                return 0;
        }

finish_force_next:
        s[sz] = 0;
        *ret = s;
        s = NULL;

        return 1;
}
