/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"
#include "util.h"

int socket_address_parse(SocketAddress *a, const char *s) {
        char *e, *n;
        unsigned u;
        int r;

        assert(a);
        assert(s);

        zero(*a);
        a->type = SOCK_STREAM;

        if (*s == '[') {
                /* IPv6 in [x:.....:z]:p notation */

                e = strchr(s+1, ']');
                if (!e)
                        return -EINVAL;

                n = strndupa(s+1, e-s-1);

                errno = 0;
                if (inet_pton(AF_INET6, n, &a->sockaddr.in6.sin6_addr) <= 0)
                        return errno > 0 ? -errno : -EINVAL;

                e++;
                if (*e != ':')
                        return -EINVAL;

                e++;
                r = safe_atou(e, &u);
                if (r < 0)
                        return r;

                if (u <= 0 || u > 0xFFFF)
                        return -EINVAL;

                a->sockaddr.in6.sin6_family = AF_INET6;
                a->sockaddr.in6.sin6_port = htobe16((uint16_t)u);
                a->size = sizeof(struct sockaddr_in6);

        } else if (*s == '/') {
                /* AF_UNIX socket */

                size_t l;

                l = strlen(s);
                if (l >= sizeof(a->sockaddr.un.sun_path))
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path, s, l);
                a->size = offsetof(struct sockaddr_un, sun_path) + l + 1;

        } else if (*s == '@') {
                /* Abstract AF_UNIX socket */
                size_t l;

                l = strlen(s+1);
                if (l >= sizeof(a->sockaddr.un.sun_path) - 1)
                        return -EINVAL;

                a->sockaddr.un.sun_family = AF_UNIX;
                memcpy(a->sockaddr.un.sun_path+1, s+1, l);
                a->size = offsetof(struct sockaddr_un, sun_path) + 1 + l;

        } else {
                e = strchr(s, ':');
                if (e) {
                        r = safe_atou(e+1, &u);
                        if (r < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        n = strndupa(s, e-s);

                        /* IPv4 in w.x.y.z:p notation? */
                        r = inet_pton(AF_INET, n, &a->sockaddr.in.sin_addr);
                        if (r < 0)
                                return -errno;

                        if (r > 0) {
                                /* Gotcha, it's a traditional IPv4 address */
                                a->sockaddr.in.sin_family = AF_INET;
                                a->sockaddr.in.sin_port = htobe16((uint16_t)u);
                                a->size = sizeof(struct sockaddr_in);
                        } else {
                                unsigned idx;

                                if (strlen(n) > IF_NAMESIZE-1)
                                        return -EINVAL;

                                /* Uh, our last resort, an interface name */
                                idx = if_nametoindex(n);
                                if (idx == 0)
                                        return -EINVAL;

                                a->sockaddr.in6.sin6_family = AF_INET6;
                                a->sockaddr.in6.sin6_port = htobe16((uint16_t)u);
                                a->sockaddr.in6.sin6_scope_id = idx;
                                a->sockaddr.in6.sin6_addr = in6addr_any;
                                a->size = sizeof(struct sockaddr_in6);
                        }
                } else {

                        /* Just a port */
                        r = safe_atou(s, &u);
                        if (r < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        if (socket_ipv6_is_supported()) {
                                a->sockaddr.in6.sin6_family = AF_INET6;
                                a->sockaddr.in6.sin6_port = htobe16((uint16_t)u);
                                a->sockaddr.in6.sin6_addr = in6addr_any;
                                a->size = sizeof(struct sockaddr_in6);
                        } else {
                                a->sockaddr.in.sin_family = AF_INET;
                                a->sockaddr.in.sin_port = htobe16((uint16_t)u);
                                a->sockaddr.in.sin_addr.s_addr = INADDR_ANY;
                                a->size = sizeof(struct sockaddr_in);
                        }
                }
        }

        return 0;
}

bool socket_ipv6_is_supported(void) {
        if (access("/proc/net/sockstat6", F_OK) != 0)
                return false;

        return true;
}

int fd_inc_sndbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        value = (int) n;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &value, sizeof(value)) < 0)
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) < 0)
                        return -errno;

        return 1;
}

int fd_inc_rcvbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        value = (int) n;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0)
                if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) < 0)
                        return -errno;
        return 1;
}
