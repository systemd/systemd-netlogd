/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>

#include "sd-network.h"
#include "socket-util.h"

typedef enum SysLogTransmissionProtocol {
        SYSLOG_TRANSMISSION_PROTOCOL_UDP      = 1 << 0,
        SYSLOG_TRANSMISSION_PROTOCOL_TCP      = 1 << 1,
        _SYSLOG_TRANSMISSION_PROTOCOL_MAX,
        _SYSLOG_TRANSMISSION_PROTOCOL_INVALID = -EINVAL,
} SysLogTransmissionProtocol;

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
        sd_journal *journal;

        char *state_file;

        char *last_cursor, *current_cursor;
        char *structured_data;
        SysLogTransmissionProtocol protocol;
};

int manager_new(Manager **ret, const char *state_file, const char *cursor);
void manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_connect(Manager *m);
void manager_disconnect(Manager *m);

void manager_close_network_socket(Manager *m);
int manager_open_network_socket(Manager *m);

int manager_push_to_network(Manager *m, int severity, int facility,
                            const char *identifier, const char *message,
                            const char *hostname, const char *pid,
                            const struct timeval *tv);

const char *protocol_to_string(int v) _const_;
int protocol_from_string(const char *s) _pure_;
