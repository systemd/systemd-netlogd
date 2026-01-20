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

static void set_priority_version_field(int severity, int facility, char *header_priority, size_t size, struct iovec *iov, int *n) {
        uint8_t makepri = (facility << 3) + severity;
        int r;

        r = snprintf(header_priority, size, "<%i>%i ", makepri, RFC_5424_PROTOCOL);
        assert(r > 0 && (size_t)r < size);
        IOVEC_SET_STRING(iov[(*n)++], header_priority);
}

static void set_timestamp_field(const struct timeval *tv, char *header_time, size_t size, struct iovec *iov, int *n) {
        format_rfc3339_timestamp(tv, header_time, size);
        IOVEC_SET_STRING(iov[(*n)++], header_time);
}

static void set_string_field_with_separator(const char *value, struct iovec *iov, int *n) {
        if (value)
                IOVEC_SET_STRING(iov[(*n)++], value);
        else
                IOVEC_SET_STRING(iov[(*n)++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[(*n)++], " ");
}

static void set_structured_data_field(Manager *m, const char *syslog_structured_data, struct iovec *iov, int *n) {
        if (m->structured_data)
                IOVEC_SET_STRING(iov[(*n)++], m->structured_data);
        else if (m->syslog_structured_data && syslog_structured_data)
                IOVEC_SET_STRING(iov[(*n)++], syslog_structured_data);
        else
                IOVEC_SET_STRING(iov[(*n)++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[(*n)++], " ");
}

static int set_message_length_field(Manager *m, char *header_msglen, size_t size, struct iovec *iov, int n, int msglen_idx) {
        size_t msglen_len;

        if (m->log_format != SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5425)
                return 0;

        msglen_len = snprintf(header_msglen, size, "%zi ", IOVEC_TOTAL_SIZE(iov, n));
        if (msglen_len >= size)
                return -EMSGSIZE;

        iov[msglen_idx].iov_base = header_msglen;
        iov[msglen_idx].iov_len = msglen_len;

        return 0;
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
        char header_msglen[1 + sizeof("99999 ")];
        struct iovec iov[15];
        int n = 0, msglen_idx = 0, r;

        assert(m);
        assert(message);

        /* Reserve space for RFC5425 message length (will be filled at the end) */
        if (m->log_format == SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5425) {
                msglen_idx = n;
                IOVEC_SET_STRING(iov[n++], "");
        }

        /* Build RFC5424 message components */
        set_priority_version_field(severity, facility, header_priority, sizeof(header_priority), iov, &n);
        set_timestamp_field(tv, header_time, sizeof(header_time), iov, &n);
        set_string_field_with_separator(hostname, iov, &n);
        set_string_field_with_separator(identifier, iov, &n);
        set_string_field_with_separator(pid, iov, &n);
        set_string_field_with_separator(syslog_msgid, iov, &n);
        set_structured_data_field(m, syslog_structured_data, iov, &n);

        /* Add message payload */
        IOVEC_SET_STRING(iov[n++], message);

        /* Add newline separator for TCP/TLS (not needed for UDP) */
        if (m->log_format == SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424 &&
            (m->protocol == SYSLOG_TRANSMISSION_PROTOCOL_TCP || m->protocol == SYSLOG_TRANSMISSION_PROTOCOL_TLS))
                IOVEC_SET_STRING(iov[n++], "\n");

        /* Compute message length for RFC5425 framing */
        r = set_message_length_field(m, header_msglen, sizeof(header_msglen), iov, n, msglen_idx);
        if (r < 0)
                return r;

        return protocol_send(m, iov, n);
}

static void set_priority_field(int severity, int facility, char *header_priority, size_t size, struct iovec *iov, int *n) {
        uint8_t makepri = (facility << 3) + severity;
        int r;

        r = snprintf(header_priority, size, "<%i>", makepri);
        assert(r > 0 && (size_t)r < size);
        IOVEC_SET_STRING(iov[(*n)++], header_priority);
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
        int n = 0;

        assert(m);
        assert(message);

        /* RFC3339 format: <pri>timestamp hostname identifier[pid]: message */
        set_priority_field(severity, facility, header_priority, sizeof(header_priority), iov, &n);
        set_timestamp_field(tv, header_time, sizeof(header_time), iov, &n);

        /* Hostname */
        if (hostname)
                IOVEC_SET_STRING(iov[n++], hostname);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], " ");

        /* Identifier[pid]: */
        if (identifier)
                IOVEC_SET_STRING(iov[n++], identifier);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], "[");

        if (pid)
                IOVEC_SET_STRING(iov[n++], pid);
        else
                IOVEC_SET_STRING(iov[n++], RFC_5424_NILVALUE);

        IOVEC_SET_STRING(iov[n++], "]: ");

        /* Message payload */
        IOVEC_SET_STRING(iov[n++], message);

        /* Add newline separator for TCP/TLS (not needed for UDP) */
        if (m->protocol == SYSLOG_TRANSMISSION_PROTOCOL_TCP || m->protocol == SYSLOG_TRANSMISSION_PROTOCOL_TLS)
                IOVEC_SET_STRING(iov[n++], "\n");

        return protocol_send(m, iov, n);
}
