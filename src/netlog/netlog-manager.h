/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>

#include "sd-network.h"
#include "socket-util.h"
#include "netlog-tls.h"

typedef enum SysLogTransmissionProtocol {
        SYSLOG_TRANSMISSION_PROTOCOL_UDP      = 1 << 0,
        SYSLOG_TRANSMISSION_PROTOCOL_TCP      = 1 << 1,
        SYSLOG_TRANSMISSION_PROTOCOL_DTLS     = 1 << 2,
        _SYSLOG_TRANSMISSION_PROTOCOL_MAX,
        _SYSLOG_TRANSMISSION_PROTOCOL_INVALID = -EINVAL,
} SysLogTransmissionProtocol;

typedef enum SysLogTransmissionLogFormat {
        SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424      = 1 << 0,
        SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_3339      = 1 << 1,
        _SYSLOG_TRANSMISSION_LOG_FORMAT_MAX,
        _SYSLOG_TRANSMISSION_LOG_FORMAT_INVALID = -EINVAL,
} SysLogTransmissionLogFormat;

typedef struct Manager Manager;

struct Manager {
        sd_event *event;
        sd_event_source *event_journal_input;
        uint64_t timeout;

        sd_event_source *sigint_event, *sigterm_event;

        /* network */
        sd_event_source *network_event_source;
        sd_network_monitor *network_monitor;

        int socket;

        /* Multicast UDP address */
        SocketAddress address;

        /* journal  */
        int journal_watch_fd;
        int namespace_flags;

        sd_journal *journal;

        char *state_file;
        char *last_cursor;
        char *current_cursor;
        char *structured_data;
        char *dir;
        char *namespace;

        SysLogTransmissionProtocol protocol;
        SysLogTransmissionLogFormat log_format;

        bool syslog_structured_data;
        bool syslog_msgid;
        bool encrypt;

        TLSManager *tls;
};

int manager_new(const char *state_file, const char *cursor, Manager **ret);
void manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);


void manager_close_network_socket(Manager *m);
int manager_open_network_socket(Manager *m);
int manager_network_connect_socket(Manager *m);

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

const char *protocol_to_string(int v) _const_;
int protocol_from_string(const char *s) _pure_;

const char *log_format_to_string(int v) _const_;
int log_format_from_string(const char *s) _pure_;
