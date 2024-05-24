/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "netlog-manager.h"

int protocol_send(Manager *m, struct iovec *iovec, unsigned n_iovec);
void format_rfc3339_timestamp(const struct timeval *tv, char *header_time, size_t header_size);
int format_rfc5424(Manager *m, int severity, int facility, const char *identifier, const char *message, const char *hostname,
                   const char *pid, const struct timeval *tv, const char *syslog_structured_data, const char *syslog_msgid);
int format_rfc3339(Manager *m, int severity, int facility, const char *identifier, const char *message, const char *hostname,
                   const char *pid, const struct timeval *tv);
