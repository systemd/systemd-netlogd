/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>

typedef struct Manager Manager;

int journal_monitor_listen(Manager *m);
int journal_event_handler(sd_event_source *event, int fd, uint32_t revents, void *userp);
void journal_close_input(Manager *m);
