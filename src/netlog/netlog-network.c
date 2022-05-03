/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>
#include <stddef.h>
#include <poll.h>
#include <netinet/tcp.h>

#include "netlog-manager.h"
#include "io-util.h"
#include "fd-util.h"

#define RFC_5424_NILVALUE "-"
#define RFC_5424_PROTOCOL 1

#define SEND_TIMEOUT_USEC (200 * USEC_PER_MSEC)

static int sendmsg_loop(Manager *m, struct msghdr *mh) {
        int r;

        assert(m);
        assert(mh);

        for (;;) {
                if (sendmsg(m->socket, mh, MSG_NOSIGNAL) >= 0)
                        return 0;

                if (errno == EINTR)
                        continue;

                if (errno != EAGAIN)
                        return -errno;

                r = fd_wait_for_event(m->socket, POLLOUT, SEND_TIMEOUT_USEC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
        }

        return 0;
}

static int network_send(Manager *m, struct iovec *iovec, unsigned n_iovec) {
        struct msghdr mh = {
                .msg_iov = iovec,
                .msg_iovlen = n_iovec,
        };

        assert(m);
        assert(iovec);
        assert(n_iovec > 0);

        if (m->address.sockaddr.sa.sa_family == AF_INET) {
                mh.msg_name = &m->address.sockaddr.sa;
                mh.msg_namelen = sizeof(m->address.sockaddr.in);
        } else if (m->address.sockaddr.sa.sa_family == AF_INET6) {
                mh.msg_name = &m->address.sockaddr.sa;
                mh.msg_namelen = sizeof(m->address.sockaddr.in6);
        } else
                return -EAFNOSUPPORT;

        return sendmsg_loop(m, &mh);
}

/* rfc3339 timestamp format: yyyy-mm-ddthh:mm:ss[.frac]<+/->zz:zz */
static void format_rfc3339_timestamp(const struct timeval *tv, char *header_time, size_t header_size) {
        char gm_buf[sizeof("+0530") + 1];
        struct tm tm;
        time_t t;

        assert(header_time);

        t = tv ? tv->tv_sec : ((time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC));
        localtime_r(&t, &tm);

        strftime(header_time, header_size, "%Y-%m-%dT%T", &tm);

        /* add fractional part */
        if (tv)
                snprintf(header_time + strlen(header_time), header_size, ".%06ld", tv->tv_usec);

        /* format the timezone according to RFC */
        xstrftime(gm_buf, "%z", &tm);
        snprintf(header_time + strlen(header_time), header_size, "%.3s:%.2s ", gm_buf, gm_buf + 3);
}

/* The Syslog Protocol RFC5424 format :
 * <pri>version sp timestamp sp hostname sp app-name sp procid sp msgid sp [sd-id]s sp msg
 */
int manager_push_to_network(Manager *m,
                            int severity,
                            int facility,
                            const char *identifier,
                            const char *message,
                            const char *hostname,
                            const char *pid,
                            const struct timeval *tv) {
        char header_priority[sizeof("<   >1 ")];
        char header_time[FORMAT_TIMESTAMP_MAX];
        uint8_t makepri;
        struct iovec iov[14];
        int n = 0;

        assert(m);
        assert(message);

        makepri = (facility << 3) + severity;

        /* First: priority field Second: Version  '<pri>version' */
        snprintf(header_priority, sizeof(header_priority), "<%i>%i ", makepri, RFC_5424_PROTOCOL);
        IOVEC_SET_STRING(iov[n++], header_priority);

        /* Third: timestamp */
        format_rfc3339_timestamp(tv, header_time, sizeof(header_time));
        IOVEC_SET_STRING(iov[n++], header_time);

        /* Fourth: hostname */
        if (hostname)
                IOVEC_SET_STRING(iov[n++], hostname);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], " ");

        /* Fifth: identifier */
        if (identifier)
                IOVEC_SET_STRING(iov[n++], identifier);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], " ");

        /* Sixth: procid */
        if (pid)
                IOVEC_SET_STRING(iov[n++], pid);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], " ");

        /* Seventh: msgid */
        IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);
        IOVEC_SET_STRING(iov[n++], " ");

        /* Eighth: [structured-data] */
        if (m->structured_data)
                IOVEC_SET_STRING(iov[n++], m->structured_data);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], " ");

        /* Ninth: message */
        IOVEC_SET_STRING(iov[n++], message);

        /* Tenth: Optional newline message separator, if not implicitly terminated by end of UDP frame */
        if (SYSLOG_TRANSMISSION_PROTOCOL_TCP == m->protocol)
                /* De facto standard: separate messages by a newline */
                IOVEC_SET_STRING(iov[n++], "\n");
        else if (SYSLOG_TRANSMISSION_PROTOCOL_UDP == m->protocol) {
                /* Message is implicitly terminated by end of UDP packet */
        } else
                return -EPROTONOSUPPORT;

        return network_send(m, iov, n);
}

void manager_close_network_socket(Manager *m) {
        assert(m);

        m->socket = safe_close(m->socket);
}

int manager_open_network_socket(Manager *m) {
        const int one = 1;
        int r;

        assert(m);

        if (!IN_SET(m->address.sockaddr.sa.sa_family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        switch (m->protocol) {
                case SYSLOG_TRANSMISSION_PROTOCOL_UDP:
                        m->socket = socket(m->address.sockaddr.sa.sa_family, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                        break;
                case SYSLOG_TRANSMISSION_PROTOCOL_TCP:
                        m->socket = socket(m->address.sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                        break;
                default:
                        return -EINVAL;
        }
        if (m->socket < 0)
                return -errno;

        r = setsockopt(m->socket, IPPROTO_IP, IP_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        if (SYSLOG_TRANSMISSION_PROTOCOL_TCP == m->protocol) {
                union sockaddr_union sa;
                socklen_t salen;
                switch (m->address.sockaddr.sa.sa_family) {
                        case AF_INET:
                                sa = (union sockaddr_union) {
                                        .in.sin_family = m->address.sockaddr.sa.sa_family,
                                        .in.sin_port = m->address.sockaddr.in.sin_port,
                                        .in.sin_addr = m->address.sockaddr.in.sin_addr,
                                };
                                salen = sizeof(sa.in);
                                break;
                        case AF_INET6:
                                sa = (union sockaddr_union) {
                                        .in6.sin6_family = m->address.sockaddr.sa.sa_family,
                                        .in6.sin6_port = m->address.sockaddr.in6.sin6_port,
                                        .in6.sin6_addr = m->address.sockaddr.in6.sin6_addr,
                                };
                                salen = sizeof(sa.in6);
                                break;
                        default:
                                r = -EAFNOSUPPORT;
                                goto fail;
                }
                r = connect(m->socket, &m->address.sockaddr.sa, salen);
                if (r < 0) {
                        r = -errno;
                        goto fail;
                }

                r = setsockopt(m->socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                if (r < 0)
                        return r;
        }

        r = fd_nonblock(m->socket, 1);
        if (r < 0)
                goto fail;

        return m->socket;

 fail:
        m->socket = safe_close(m->socket);

        return r;
}
