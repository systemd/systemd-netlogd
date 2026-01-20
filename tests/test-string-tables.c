/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "netlog-manager.h"

/* Test protocol string table conversions */
static void test_protocol_string_table(void **state) {
        assert_string_equal(protocol_to_string(SYSLOG_TRANSMISSION_PROTOCOL_UDP), "udp");
        assert_string_equal(protocol_to_string(SYSLOG_TRANSMISSION_PROTOCOL_TCP), "tcp");
        assert_string_equal(protocol_to_string(SYSLOG_TRANSMISSION_PROTOCOL_DTLS), "dtls");
        assert_string_equal(protocol_to_string(SYSLOG_TRANSMISSION_PROTOCOL_TLS), "tls");

        assert_int_equal(protocol_from_string("udp"), SYSLOG_TRANSMISSION_PROTOCOL_UDP);
        assert_int_equal(protocol_from_string("tcp"), SYSLOG_TRANSMISSION_PROTOCOL_TCP);
        assert_int_equal(protocol_from_string("dtls"), SYSLOG_TRANSMISSION_PROTOCOL_DTLS);
        assert_int_equal(protocol_from_string("tls"), SYSLOG_TRANSMISSION_PROTOCOL_TLS);

        /* Test invalid protocol - returns -1 when not found */
        assert_true(protocol_from_string("invalid") < 0);
        assert_null(protocol_to_string(999));
}

/* Test log format string table conversions */
static void test_log_format_string_table(void **state) {
        assert_string_equal(log_format_to_string(SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424), "rfc5424");
        assert_string_equal(log_format_to_string(SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_3339), "rfc3339");
        assert_string_equal(log_format_to_string(SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5425), "rfc5425");

        assert_int_equal(log_format_from_string("rfc5424"), SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424);
        assert_int_equal(log_format_from_string("rfc3339"), SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_3339);
        assert_int_equal(log_format_from_string("rfc5425"), SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5425);

        /* Test invalid format - returns -1 when not found */
        assert_true(log_format_from_string("invalid") < 0);
        assert_null(log_format_to_string(999));
}

/* Test syslog facility string table conversions */
static void test_syslog_facility_string_table(void **state) {
        assert_string_equal(syslog_facility_to_string(SYSLOG_FACILITY_KERN), "kern");
        assert_string_equal(syslog_facility_to_string(SYSLOG_FACILITY_USER), "user");
        assert_string_equal(syslog_facility_to_string(SYSLOG_FACILITY_MAIL), "mail");
        assert_string_equal(syslog_facility_to_string(SYSLOG_FACILITY_DAEMON), "daemon");
        assert_string_equal(syslog_facility_to_string(SYSLOG_FACILITY_AUTH), "auth");
        assert_string_equal(syslog_facility_to_string(SYSLOG_FACILITY_LOCAL0), "local0");
        assert_string_equal(syslog_facility_to_string(SYSLOG_FACILITY_LOCAL7), "local7");

        assert_int_equal(syslog_facility_from_string("kern"), SYSLOG_FACILITY_KERN);
        assert_int_equal(syslog_facility_from_string("user"), SYSLOG_FACILITY_USER);
        assert_int_equal(syslog_facility_from_string("local0"), SYSLOG_FACILITY_LOCAL0);

        /* Test invalid facility - returns -1 when not found */
        assert_true(syslog_facility_from_string("invalid") < 0);
        assert_null(syslog_facility_to_string(999));
}

/* Test syslog level string table conversions */
static void test_syslog_level_string_table(void **state) {
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_EMERGENCY), "emerg");
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_ALERT), "alert");
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_CRITICAL), "crit");
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_ERROR), "err");
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_WARNING), "warning");
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_NOTICE), "notice");
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_INFORMATIONAL), "info");
        assert_string_equal(syslog_level_to_string(SYSLOG_LEVEL_DEBUG), "debug");

        assert_int_equal(syslog_level_from_string("emerg"), SYSLOG_LEVEL_EMERGENCY);
        assert_int_equal(syslog_level_from_string("debug"), SYSLOG_LEVEL_DEBUG);

        /* Test invalid level - returns -1 when not found */
        assert_true(syslog_level_from_string("invalid") < 0);
        assert_null(syslog_level_to_string(999));
}

int main(void) {
        const struct CMUnitTest tests[] = {
                cmocka_unit_test(test_protocol_string_table),
                cmocka_unit_test(test_log_format_string_table),
                cmocka_unit_test(test_syslog_facility_string_table),
                cmocka_unit_test(test_syslog_level_string_table),
        };

        return cmocka_run_group_tests(tests, NULL, NULL);
}
