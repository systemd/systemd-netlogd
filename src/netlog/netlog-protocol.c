/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/tcp.h>
#include <poll.h>
#include <stddef.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "netlog-protocol.h"
#include "netlog-network.h"

#define RFC_5424_NILVALUE "-"
#define RFC_5424_PROTOCOL 1

#define SEND_TIMEOUT_USEC (200 * USEC_PER_MSEC)

int protocol_send(Manager *m, struct iovec *iovec, unsigned n_iovec) {
        int r;

        switch (m->protocol) {
                case SYSLOG_TRANSMISSION_PROTOCOL_DTLS:
                        r = dtls_datagram_writev(m->dtls, iovec, n_iovec);
                        if (r < 0 && r != -EAGAIN) {
                                log_debug_errno(r, "Failed to send via DTLS, performing reconnect: %m");
                                manager_connect(m);
                                return r;
                        }
                        break;
                case SYSLOG_TRANSMISSION_PROTOCOL_TLS:
                        r = tls_stream_writev(m->tls, iovec, n_iovec);
                        if (r < 0 && r != -EAGAIN) {
                                log_debug_errno(r, "Failed to send via TLS, performing reconnect: %m");
                                manager_connect(m);
                                return r;
                        }
                        break;
                default:
                       r = network_send(m, iovec, n_iovec);
                        if (r < 0 && r != -EAGAIN) {
                                log_debug_errno(r, "Failed to send via %s, performing reconnect: %m", protocol_to_string(m->protocol));
                                manager_connect(m);
                                return r;
                        }
                        break;
        }

        return 0;
}

/* rfc3339 timestamp format: yyyy-mm-ddthh:mm:ss[.frac]<+/->zz:zz */
void format_rfc3339_timestamp(const struct timeval *tv, char *header_time, size_t header_size) {
        char gm_buf[sizeof("+0530") + 1];
        struct tm tm;
        time_t t;
        size_t w;
        int r;

        assert(header_time);

        t = tv ? tv->tv_sec : ((time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC));
        localtime_r(&t, &tm);

        w = strftime(header_time, header_size, "%Y-%m-%dT%T", &tm);
        assert(w != 0);
        header_time += w;
        header_size -= w;

        /* add fractional part */
        if (tv) {
                r = snprintf(header_time, header_size, ".%06lld", (long long)tv->tv_usec);
                assert(r > 0 && (size_t)r < header_size);
                header_time += r;
                header_size -= r;
        }

        /* format the timezone according to RFC */
        xstrftime(gm_buf, "%z", &tm);
        r = snprintf(header_time, header_size, "%.3s:%.2s ", gm_buf, gm_buf + 3);
        assert(r > 0 && (size_t)r < header_size);
}

/* The Syslog Protocol RFC5424 format :
 * <pri>version sp timestamp sp hostname sp app-name sp procid sp msgid sp [sd-id]s sp msg
 */
int format_rfc5424(Manager *m,
                   int severity,
                   int facility,
                   const char *identifier,
                   const char *message,
                   const char *hostname,
                   const char *pid,
                   const struct timeval *tv,
                   const char *syslog_structured_data,
                   const char *syslog_msgid) {

        char header_time[FORMAT_TIMESTAMP_MAX];
        char header_priority[sizeof("<   >1 ")];
        struct iovec iov[14];
        uint8_t makepri;
        int n = 0, r;

        assert(m);
        assert(message);

        makepri = (facility << 3) + severity;

        /* First: priority field Second: Version  '<pri>version' */
        r = snprintf(header_priority, sizeof(header_priority), "<%i>%i ", makepri, RFC_5424_PROTOCOL);
        assert(r > 0 && (size_t)r < sizeof(header_priority));
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
        if (syslog_msgid)
                IOVEC_SET_STRING(iov[n++], syslog_msgid);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], " ");

        /* Eighth: [structured-data] */
        if (m->structured_data)
                IOVEC_SET_STRING(iov[n++], m->structured_data);
        else if (m->syslog_structured_data && syslog_structured_data)
                IOVEC_SET_STRING(iov[n++], syslog_structured_data);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], " ");

        /* Ninth: message */
        IOVEC_SET_STRING(iov[n++], message);

        /* Last Optional newline message separator, if not implicitly terminated by end of UDP frame
         * De facto standard: separate messages by a newline
         */
        if (m->protocol == SYSLOG_TRANSMISSION_PROTOCOL_TCP)
                IOVEC_SET_STRING(iov[n++], "\n");

        return protocol_send(m, iov, n);
}

int format_rfc3339(Manager *m,
                   int severity,
                   int facility,
                   const char *identifier,
                   const char *message,
                   const char *hostname,
                   const char *pid,
                   const struct timeval *tv) {

        char header_priority[sizeof("<   >1 ")];
        char header_time[FORMAT_TIMESTAMP_MAX];
        struct iovec iov[14];
        uint8_t makepri;
        int n = 0, r;

        assert(m);
        assert(message);

        makepri = (facility << 3) + severity;

        /* rfc3339
         * <35>Oct 12 22:14:15 client_machine su: 'su root' failed for joe on /dev/pts/2
         */

        /* First: priority field '<pri>' */
        r = snprintf(header_priority, sizeof(header_priority), "<%i>", makepri);
        assert(r > 0 && (size_t)r < sizeof(header_priority));
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

        IOVEC_SET_STRING(iov[n++], "[");

        /* Sixth: procid */
        if (pid)
                IOVEC_SET_STRING(iov[n++], pid);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], "]: ");

        /* Ninth: message */
        IOVEC_SET_STRING(iov[n++], message);

        /* Last Optional newline message separator, if not implicitly terminated by end of UDP frame
         * De facto standard: separate messages by a newline
         */
        if (m->protocol == SYSLOG_TRANSMISSION_PROTOCOL_TCP)
                IOVEC_SET_STRING(iov[n++], "\n");

        return protocol_send(m, iov, n);
}
