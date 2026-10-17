/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "socket-util.h"

#include "netlog-ssl-common.h"

static int socket_domain(int fd) {
        int domain = -1;
        socklen_t l = sizeof(domain);

        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &l) < 0)
                return -errno;

        return domain;
}

static int socket_type(int fd) {
        int type = -1;
        socklen_t l = sizeof(type);

        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &l) < 0)
                return -errno;

        return type;
}

/* TLS over IPv6: the regression that motivated this test. */
static void test_ssl_socket_ipv6_tls(void **state) {
        SocketAddress a;
        int fd;

        zero(a);
        assert_int_equal(socket_address_parse(&a, "[::1]:6514"), 0);
        assert_int_equal(a.sockaddr.sa.sa_family, AF_INET6);

        fd = ssl_socket(&a, SSL_TRANSPORT_TLS);
        assert_return_code(fd, 0);

        assert_int_equal(socket_domain(fd), AF_INET6);
        assert_int_equal(socket_type(fd), SOCK_STREAM);

        safe_close(fd);
}

/* TLS over IPv4: symmetric baseline guarding against accidental AF removal. */
static void test_ssl_socket_ipv4_tls(void **state) {
        SocketAddress a;
        int fd;

        zero(a);
        assert_int_equal(socket_address_parse(&a, "127.0.0.1:6514"), 0);
        assert_int_equal(a.sockaddr.sa.sa_family, AF_INET);

        fd = ssl_socket(&a, SSL_TRANSPORT_TLS);
        assert_return_code(fd, 0);

        assert_int_equal(socket_domain(fd), AF_INET);
        assert_int_equal(socket_type(fd), SOCK_STREAM);

        safe_close(fd);
}

/* DTLS shares ssl_socket(); exercise the datagram branch over IPv6. */
static void test_ssl_socket_ipv6_dtls(void **state) {
        SocketAddress a;
        int fd;

        zero(a);
        assert_int_equal(socket_address_parse(&a, "[::1]:4433"), 0);

        fd = ssl_socket(&a, SSL_TRANSPORT_DTLS);
        assert_return_code(fd, 0);

        assert_int_equal(socket_domain(fd), AF_INET6);
        assert_int_equal(socket_type(fd), SOCK_DGRAM);

        safe_close(fd);
}

/* DTLS shares ssl_socket(); exercise the datagram branch over IPv4. */
static void test_ssl_socket_ipv4_dtls(void **state) {
        SocketAddress a;
        int fd;

        zero(a);
        assert_int_equal(socket_address_parse(&a, "127.0.0.1:4433"), 0);
        assert_int_equal(a.sockaddr.sa.sa_family, AF_INET);

        fd = ssl_socket(&a, SSL_TRANSPORT_DTLS);
        assert_return_code(fd, 0);

        assert_int_equal(socket_domain(fd), AF_INET);
        assert_int_equal(socket_type(fd), SOCK_DGRAM);

        safe_close(fd);
}


/* Unsupported families must be rejected early. */
static void test_ssl_socket_unsupported_family(void **state) {
        SocketAddress a;

        zero(a);
        a.sockaddr.sa.sa_family = AF_UNIX;

        assert_int_equal(ssl_socket(&a, SSL_TRANSPORT_TLS), -EAFNOSUPPORT);
}

int main(void) {
        const struct CMUnitTest tests[] = {
                cmocka_unit_test(test_ssl_socket_ipv6_tls),
                cmocka_unit_test(test_ssl_socket_ipv4_tls),
                cmocka_unit_test(test_ssl_socket_ipv6_dtls),
                cmocka_unit_test(test_ssl_socket_ipv4_dtls),
                cmocka_unit_test(test_ssl_socket_unsupported_family),
        };

        return cmocka_run_group_tests(tests, NULL, NULL);
}
