/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "dns-domain.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "macro.h"
#include "parse-util.h"
#include "string-util.h"

int dns_label_unescape(const char **name, char *dest, size_t sz, DNSLabelFlags flags) {
        const char *n;
        char *d, last_char = 0;
        int r = 0;

        assert(name);
        assert(*name);

        n = *name;
        d = dest;

        for (;;) {
                if (IN_SET(*n, 0, '.')) {
                        if (FLAGS_SET(flags, DNS_LABEL_LDH) && last_char == '-')
                                /* Trailing dash */
                                return -EINVAL;

                        if (n[0] == '.' && (n[1] != 0 || !FLAGS_SET(flags, DNS_LABEL_LEAVE_TRAILING_DOT)))
                                n++;

                        break;
                }

                if (r >= DNS_LABEL_MAX)
                        return -EINVAL;

                if (sz <= 0)
                        return -ENOBUFS;

                if (*n == '\\') {
                        /* Escaped character */
                        if (FLAGS_SET(flags, DNS_LABEL_NO_ESCAPES))
                                return -EINVAL;

                        n++;

                        if (*n == 0)
                                /* Ending NUL */
                                return -EINVAL;

                        else if (IN_SET(*n, '\\', '.')) {
                                /* Escaped backslash or dot */

                                if (FLAGS_SET(flags, DNS_LABEL_LDH))
                                        return -EINVAL;

                                last_char = *n;
                                if (d)
                                        *(d++) = *n;
                                sz--;
                                r++;
                                n++;

                        } else if (n[0] >= '0' && n[0] <= '9') {
                                unsigned k;

                                /* Escaped literal ASCII character */

                                if (!(n[1] >= '0' && n[1] <= '9') ||
                                    !(n[2] >= '0' && n[2] <= '9'))
                                        return -EINVAL;

                                k = ((unsigned) (n[0] - '0') * 100) +
                                        ((unsigned) (n[1] - '0') * 10) +
                                        ((unsigned) (n[2] - '0'));

                                /* Don't allow anything that doesn't fit in 8 bits. Note that we do allow
                                 * control characters, as some servers (e.g. cloudflare) are happy to
                                 * generate labels with them inside. */
                                if (k > 255)
                                        return -EINVAL;

                                if (FLAGS_SET(flags, DNS_LABEL_LDH) &&
                                    !valid_ldh_char((char) k))
                                        return -EINVAL;

                                last_char = (char) k;
                                if (d)
                                        *(d++) = (char) k;
                                sz--;
                                r++;

                                n += 3;
                        } else
                                return -EINVAL;

                } else if ((uint8_t) *n >= (uint8_t) ' ' && *n != 127) {

                        /* Normal character */

                        if (FLAGS_SET(flags, DNS_LABEL_LDH)) {
                                if (!valid_ldh_char(*n))
                                        return -EINVAL;
                                if (r == 0 && *n == '-')
                                        /* Leading dash */
                                        return -EINVAL;
                        }

                        last_char = *n;
                        if (d)
                                *(d++) = *n;
                        sz--;
                        r++;
                        n++;
                } else
                        return -EINVAL;
        }

        /* Empty label that is not at the end? */
        if (r == 0 && *n)
                return -EINVAL;

        /* More than one trailing dot? */
        if (n[0] == '.' && !FLAGS_SET(flags, DNS_LABEL_LEAVE_TRAILING_DOT))
                return -EINVAL;

        if (sz >= 1 && d)
                *d = 0;

        *name = n;
        return r;
}

int dns_label_escape(const char *p, size_t l, char *dest, size_t sz) {
        char *q;

        /* DNS labels must be between 1 and 63 characters long. A
         * zero-length label does not exist. See RFC 2181, Section
         * 11. */

        if (l <= 0 || l > DNS_LABEL_MAX)
                return -EINVAL;
        if (sz < 1)
                return -ENOBUFS;

        assert(p);
        assert(dest);

        q = dest;
        while (l > 0) {

                if (IN_SET(*p, '.', '\\')) {

                        /* Dot or backslash */

                        if (sz < 3)
                                return -ENOBUFS;

                        *(q++) = '\\';
                        *(q++) = *p;

                        sz -= 2;

                } else if (IN_SET(*p, '_', '-') ||
                           ascii_isdigit(*p) ||
                           ascii_isalpha(*p)) {

                        /* Proper character */

                        if (sz < 2)
                                return -ENOBUFS;

                        *(q++) = *p;
                        sz -= 1;

                } else {

                        /* Everything else */

                        if (sz < 5)
                                return -ENOBUFS;

                        *(q++) = '\\';
                        *(q++) = '0' + (char) ((uint8_t) *p / 100);
                        *(q++) = '0' + (char) (((uint8_t) *p / 10) % 10);
                        *(q++) = '0' + (char) ((uint8_t) *p % 10);

                        sz -= 4;
                }

                p++;
                l--;
        }

        *q = 0;
        return (int) (q - dest);
}

int dns_name_concat(const char *a, const char *b, DNSLabelFlags flags, char **_ret) {
        _cleanup_free_ char *ret = NULL;
        size_t allocated = 0,  n = 0;
        const char *p;
        bool first = true;
        int r;

        if (a)
                p = a;
        else if (b)
                p = TAKE_PTR(b);
        else
                goto finish;

        for (;;) {
                char label[DNS_LABEL_MAX+1];

                r = dns_label_unescape(&p, label, sizeof label, flags);
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (*p != 0)
                                return -EINVAL;

                        if (b) {
                                /* Now continue with the second string, if there is one */
                                p = TAKE_PTR(b);
                                continue;
                        }

                        break;
                }

                if (_ret) {
                        if (!GREEDY_REALLOC(ret, allocated, n + !first + DNS_LABEL_ESCAPED_MAX))
                                return -ENOMEM;

                        r = dns_label_escape(label, r, ret + n + !first, DNS_LABEL_ESCAPED_MAX);
                        if (r < 0)
                                return r;

                        if (!first)
                                ret[n] = '.';
                } else {
                        char escaped[DNS_LABEL_ESCAPED_MAX];

                        r = dns_label_escape(label, r, escaped, sizeof(escaped));
                        if (r < 0)
                                return r;
                }

                n += r + !first;
                first = false;
        }

finish:
        if (n > DNS_HOSTNAME_MAX)
                return -EINVAL;

        if (_ret) {
                if (n == 0) {
                        /* Nothing appended? If so, generate at least a single dot, to indicate the DNS root domain */
                        if (!GREEDY_REALLOC(ret, allocated, 2))
                                return -ENOMEM;

                        ret[n++] = '.';
                } else {
                        if (!GREEDY_REALLOC(ret, allocated, n + 1))
                                return -ENOMEM;
                }

                ret[n] = 0;
                *_ret = TAKE_PTR(ret);
        }

        return 0;
}

int dns_name_is_valid_or_address(const char *name) {
        /* Returns > 0 if the specified name is either a valid IP address formatted as string or a valid DNS name */

        if (isempty(name))
                return 0;

        if (in_addr_from_string_auto(name, NULL, NULL) >= 0)
                return 1;

        return dns_name_is_valid(name);
}

