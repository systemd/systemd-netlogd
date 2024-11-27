/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>

#include "netlog-dtls.h"
#include "netlog-tls.h"
#include "sd-network.h"
#include "sd-resolve.h"
#include "socket-util.h"
#include "ratelimit.h"

#define DEFAULT_CONNECTION_RETRY_USEC   (30 * USEC_PER_SEC)

typedef enum SysLogTransmissionProtocol {
        SYSLOG_TRANSMISSION_PROTOCOL_UDP      = 1 << 0,
        SYSLOG_TRANSMISSION_PROTOCOL_TCP      = 1 << 1,
        SYSLOG_TRANSMISSION_PROTOCOL_DTLS     = 1 << 2,
        SYSLOG_TRANSMISSION_PROTOCOL_TLS      = 1 << 3,
        _SYSLOG_TRANSMISSION_PROTOCOL_MAX,
        _SYSLOG_TRANSMISSION_PROTOCOL_INVALID = -EINVAL,
} SysLogTransmissionProtocol;

typedef enum SysLogTransmissionLogFormat {
        SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424      = 1 << 0,
        SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_3339      = 1 << 1,
        _SYSLOG_TRANSMISSION_LOG_FORMAT_MAX,
        _SYSLOG_TRANSMISSION_LOG_FORMAT_INVALID = -EINVAL,
} SysLogTransmissionLogFormat;

/* RFC 5424 Section 6.2.1 */
typedef enum SysLogFacility {
        SYSLOG_FACILITY_KERN         =  0,
        SYSLOG_FACILITY_USER         =  1,
        SYSLOG_FACILITY_MAIL         =  2,
        SYSLOG_FACILITY_DAEMON       =  3,
        SYSLOG_FACILITY_AUTH         =  4,
        SYSLOG_FACILITY_SYSLOG       =  5,
        SYSLOG_FACILITY_LPR          =  6,
        SYSLOG_FACILITY_NEWS         =  7,
        SYSLOG_FACILITY_UUCP         =  8,
        SYSLOG_FACILITY_CRON         =  9,
        SYSLOG_FACILITY_AUTHPRIV     = 10,
        SYSLOG_FACILITY_FTP          = 11,
        SYSLOG_FACILITY_NTP          = 12,
        SYSLOG_FACILITY_SECURITY     = 13,
        SYSLOG_FACILITY_CONSOLE      = 14,
        SYSLOG_FACILITY_SOLARIS_CRON = 15,
        SYSLOG_FACILITY_LOCAL0       = 16,
        SYSLOG_FACILITY_LOCAL1       = 17,
        SYSLOG_FACILITY_LOCAL2       = 18,
        SYSLOG_FACILITY_LOCAL3       = 19,
        SYSLOG_FACILITY_LOCAL4       = 20,
        SYSLOG_FACILITY_LOCAL5       = 21,
        SYSLOG_FACILITY_LOCAL6       = 22,
        SYSLOG_FACILITY_LOCAL7       = 23,
        _SYSLOG_FACILITY_MAX,
        _SYSLOG_FACILITY_INVALID     = -EINVAL,
} SysLogFacility;

/* RFC 5424 Section 6.2.1 */
typedef enum SysLogLevel {
        SYSLOG_LEVEL_EMERGENCY     = 0,
        SYSLOG_LEVEL_ALERT         = 1,
        SYSLOG_LEVEL_CRITICAL      = 2,
        SYSLOG_LEVEL_ERROR         = 3,
        SYSLOG_LEVEL_WARNING       = 4,
        SYSLOG_LEVEL_NOTICE        = 5,
        SYSLOG_LEVEL_INFORMATIONAL = 6,
        SYSLOG_LEVEL_DEBUG         = 7,
        _SYSLOG_LEVEL_MAX,
        _SYSLOG_LEVEL_INVALID      = -EINVAL,
} SysLogLevel;

typedef struct Manager Manager;

struct Manager {
        sd_resolve *resolve;
        sd_event *event;

        sd_event_source *event_journal_input;
        usec_t connection_retry_usec;

        /* network */
        sd_event_source *network_event_source;
        sd_network_monitor *network_monitor;

        /* Retry connections */
        sd_event_source *event_retry;

        RateLimit ratelimit;

        /* peer */
        sd_resolve_query *resolve_query;

        int socket;

        /* Multicast UDP address */
        SocketAddress address;
        uint32_t port;

        char *server_name;

        uint32_t excluded_syslog_facilities;
        uint8_t excluded_syslog_levels;

        /* journal  */
        int journal_watch_fd;
        int namespace_flags;

        sd_journal *journal;

        char *state_file;
        char *last_cursor;
        char *structured_data;
        char *dir;
        char *namespace;

        SysLogTransmissionProtocol protocol;
        SysLogTransmissionLogFormat log_format;
        OpenSSLCertificateAuthMode auth_mode;
        char *server_cert;

        bool syslog_structured_data;
        bool syslog_msgid;

        DTLSManager *dtls;
        TLSManager *tls;

        bool keep_alive;
        bool no_delay;
        bool connected;
        bool resolving;

        unsigned keep_alive_cnt;

        size_t send_buffer;

        usec_t keep_alive_time;
        usec_t keep_alive_interval;
};

int manager_new(const char *state_file, const char *cursor, Manager **ret);
void manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);

void manager_close_network_socket(Manager *m);
int manager_open_network_socket(Manager *m);
int manager_network_connect_socket(Manager *m);

int manager_resolve_handler(sd_resolve_query *q, int ret, const struct addrinfo *ai, void *userdata);

int manager_push_to_network(Manager *m,
                            int severity,
                            int facility,
                            const char *identifier,
                            const char *message,
                            const char *hostname,
                            const char *pid,
                            const struct timeval *tv,
                            const char *syslog_structured_data,
                            const char *syslog_msgid);

const char *protocol_to_string(SysLogTransmissionProtocol v) _const_;
SysLogTransmissionProtocol protocol_from_string(const char *s) _pure_;

const char *log_format_to_string(SysLogTransmissionLogFormat v) _const_;
SysLogTransmissionLogFormat log_format_from_string(const char *s) _pure_;

const char *syslog_facility_to_string(SysLogFacility v) _const_;
SysLogFacility syslog_facility_from_string(const char *s) _pure_;

const char *syslog_level_to_string(SysLogLevel v) _const_;
SysLogLevel syslog_level_from_string(const char *s) _pure_;
