/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

int config_parse_protocol(const char *unit,
                          const char *filename,
                          unsigned line,
                          const char *section,
                          unsigned section_line,
                          const char *lvalue,
                          int ltype,
                          const char *rvalue,
                          void *data,
                          void *userdata);

int config_parse_log_format(const char *unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata);

int config_parse_tls_certificate_auth_mode(const char *unit,
                                           const char *filename,
                                           unsigned line,
                                           const char *section,
                                           unsigned section_line,
                                           const char *lvalue,
                                           int ltype,
                                           const char *rvalue,
                                           void *data,
                                           void *userdata);

int config_parse_namespace(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata);

int config_parse_syslog_facility(const char *unit,
                                 const char *filename,
                                 unsigned line,
                                 const char *section,
                                 unsigned section_line,
                                 const char *lvalue,
                                 int ltype,
                                 const char *rvalue,
                                 void *data,
                                 void *userdata);

int config_parse_syslog_level(const char *unit,
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
