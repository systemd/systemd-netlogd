/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"

#define MODE_INVALID ((mode_t) -1)

int parse_boolean(const char *v) _pure_;
int parse_ifindex(const char *s, int *ret);

#define FORMAT_BYTES_MAX 8

int safe_atou(const char *s, unsigned *ret_u);
int safe_atoi(const char *s, int *ret_i);
int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atolli(const char *s, long long int *ret_i);

static inline int safe_atou32(const char *s, uint32_t *ret_u) {
        assert_cc(sizeof(uint32_t) == sizeof(unsigned));
        return safe_atou(s, (unsigned*) ret_u);
}

#if LONG_MAX == INT_MAX
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned));
        return safe_atou(s, (unsigned*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(int));
        return safe_atoi(s, (int*) ret_u);
}
#else
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned long long));
        return safe_atollu(s, (unsigned long long*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(long long int));
        return safe_atolli(s, (long long int*) ret_u);
}
#endif
