/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Susant Sahani
***/

#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>

#include "sd-network.h"
#include "socket-util.h"

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

        char *last_cursor;
        char *structured_data;
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
