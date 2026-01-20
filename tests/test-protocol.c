/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "macro.h"
#include "time-util.h"

#define FORMAT_TIMESTAMP_MAX ((4*4+1)+11+9+4+1) /* weekdays can be unicode */

/* Forward declaration from netlog-protocol.c */
void format_rfc3339_timestamp(const struct timeval *tv, char *header_time, size_t header_size);

/* Test RFC 3339 timestamp formatting */
static void test_format_rfc3339_timestamp(void **state) {
        char buf[FORMAT_TIMESTAMP_MAX];
        struct timeval tv = {
                .tv_sec = 1234567890,
                .tv_usec = 123456,
        };

        format_rfc3339_timestamp(&tv, buf, sizeof(buf));

        /* Should contain year 2009 (timestamp 1234567890) */
        assert_non_null(strstr(buf, "2009"));
        /* Should contain microseconds */
        assert_non_null(strstr(buf, ".123456"));
        /* Should contain timezone offset in RFC3339 format (colon separated) */
        assert_true(strchr(buf, ':') != NULL);
}

/* Test RFC 3339 timestamp with NULL tv (current time) */
static void test_format_rfc3339_timestamp_null(void **state) {
        char buf[FORMAT_TIMESTAMP_MAX];

        format_rfc3339_timestamp(NULL, buf, sizeof(buf));

        /* Should contain a valid timestamp */
        assert_int_not_equal(strlen(buf), 0);
        /* Should contain year 20xx */
        assert_non_null(strstr(buf, "20"));
}

/* Test RFC 3339 timestamp format structure */
static void test_rfc3339_timestamp_structure(void **state) {
        char buf[FORMAT_TIMESTAMP_MAX];
        struct timeval tv = {
                .tv_sec = 1609459200, /* 2021-01-01 00:00:00 UTC */
                .tv_usec = 500000,
        };

        format_rfc3339_timestamp(&tv, buf, sizeof(buf));

        /* Check for T separator */
        assert_non_null(strchr(buf, 'T'));
        /* Check for microseconds with dot */
        assert_non_null(strstr(buf, ".500000"));
}

int main(void) {
        const struct CMUnitTest tests[] = {
                cmocka_unit_test(test_format_rfc3339_timestamp),
                cmocka_unit_test(test_format_rfc3339_timestamp_null),
                cmocka_unit_test(test_rfc3339_timestamp_structure),
        };

        return cmocka_run_group_tests(tests, NULL, NULL);
}
