/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

#include "macro.h"
#include "util.h"

union in_addr_union {
        struct in_addr in;
        struct in6_addr in6;
};

struct in_addr_data {
        int family;
        union in_addr_union address;
};

bool in4_addr_is_null(const struct in_addr *a);
bool in6_addr_is_null(const struct in6_addr *a);

int in_addr_is_null(int family, const union in_addr_union *u);
int in_addr_is_link_local(int family, const union in_addr_union *u);
int in_addr_is_localhost(int family, const union in_addr_union *u);
int in_addr_equal(int family, const union in_addr_union *a, const union in_addr_union *b);
int in_addr_prefix_intersect(int family, const union in_addr_union *a, unsigned aprefixlen, const union in_addr_union *b, unsigned bprefixlen);
int in_addr_prefix_next(int family, union in_addr_union *u, unsigned prefixlen);
int in_addr_to_string(int family, const union in_addr_union *u, char **ret);
int in_addr_ifindex_to_string(int family, const union in_addr_union *u, int ifindex, char **ret);
int in_addr_from_string(int family, const char *s, union in_addr_union *ret);
int in_addr_from_string_auto(const char *s, int *family, union in_addr_union *ret);
int in_addr_ifindex_from_string_auto(const char *s, int *family, union in_addr_union *ret, int *ifindex);
unsigned char in_addr_netmask_to_prefixlen(const struct in_addr *addr);
struct in_addr* in_addr_prefixlen_to_netmask(struct in_addr *addr, unsigned char prefixlen);
int in_addr_default_prefixlen(const struct in_addr *addr, unsigned char *prefixlen);
int in_addr_default_subnet_mask(const struct in_addr *addr, struct in_addr *mask);
int in_addr_mask(int family, union in_addr_union *addr, unsigned char prefixlen);

static inline size_t FAMILY_ADDRESS_SIZE(int family) {
        assert(family == AF_INET || family == AF_INET6);
        return family == AF_INET6 ? 16 : 4;
}

#define IN_ADDR_NULL ((union in_addr_union) {})

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define IN_ADDR_MAX CONST_MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)
#define IN_ADDR_TO_STRING(family, addr) typesafe_inet_ntop(family, addr, (char[IN_ADDR_MAX]){}, IN_ADDR_MAX)
#define IN4_ADDR_TO_STRING(addr) typesafe_inet_ntop4(addr, (char[INET_ADDRSTRLEN]){}, INET_ADDRSTRLEN)
#define IN6_ADDR_TO_STRING(addr) typesafe_inet_ntop6(addr, (char[INET6_ADDRSTRLEN]){}, INET6_ADDRSTRLEN)
