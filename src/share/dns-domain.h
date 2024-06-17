/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns-def.h"
#include "hashmap.h"
#include "in-addr-util.h"

typedef enum DNSLabelFlags {
        DNS_LABEL_LDH                = 1 << 0, /* Follow the "LDH" rule — only letters, digits, and internal hyphens. */
        DNS_LABEL_NO_ESCAPES         = 1 << 1, /* Do not treat backslashes specially */
        DNS_LABEL_LEAVE_TRAILING_DOT = 1 << 2, /* Leave trailing dot in place */
} DNSLabelFlags;

int dns_name_concat(const char *a, const char *b, DNSLabelFlags flags, char **ret);

static inline int dns_name_normalize(const char *s, DNSLabelFlags flags, char **ret) {
        /* dns_name_concat() normalizes as a side-effect */
        return dns_name_concat(s, NULL, flags, ret);
}

static inline int dns_name_is_valid(const char *s) {
        int r;

        /* dns_name_concat() verifies as a side effect */
        r = dns_name_concat(s, NULL, 0, NULL);
        if (r == -EINVAL)
                return 0;
        if (r < 0)
                return r;
        return 1;
}

int dns_label_unescape(const char **name, char *dest, size_t sz, DNSLabelFlags flags);
int dns_label_escape(const char *p, size_t l, char *dest, size_t sz);
int dns_name_address(const char *p, int *family, union in_addr_union *a);
int dns_name_is_valid_or_address(const char *name);
