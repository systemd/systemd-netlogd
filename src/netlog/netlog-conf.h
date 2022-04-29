/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "in-addr-util.h"
#include "conf-parser.h"
#include "netlog-manager.h"

const struct ConfigPerfItem* netlog_gperf_lookup(const char *key, size_t length);
int config_parse_netlog_remote_address(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata);
int config_parse_socket_type(const char *unit,
                             const char *filename,
                             unsigned line,
                             const char *section,
                             unsigned section_line,
                             const char *lvalue,
                             int ltype,
                             const char *rvalue,
                             void *data,
                             void *userdata);
int manager_parse_config_file(Manager *m);
