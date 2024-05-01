/* SPDX-License-Identifier: LGPL-2.1+ */

#include "def.h"
#include "in-addr-util.h"
#include "netlog-conf.h"
#include "conf-parser.h"
#include "string-util.h"

int config_parse_netlog_remote_address(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = socket_address_parse(&m->address, rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, -r, "Failed to parse '%s=%s', ignoring.", lvalue, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_protocol(const char *unit,
                             const char *filename,
                             unsigned line,
                             const char *section,
                             unsigned section_line,
                             const char *lvalue,
                             int ltype,
                             const char *rvalue,
                             void *data,
                             void *userdata) {
        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = protocol_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, -r, "Failed to parse '%s=%s', ignoring.", lvalue, rvalue);
                return 0;
        }

        m->protocol = r;
        return 0;
}

int config_parse_log_format(const char *unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata) {
        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = log_format_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, -r, "Failed to parse '%s=%s', ignoring.", lvalue, rvalue);
                return 0;
        }

        m->log_format = r;
        return 0;
}

int config_parse_namespace(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {
        Manager *m = userdata;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

         if (streq(rvalue, "*"))
                 m->namespace_flags = SD_JOURNAL_ALL_NAMESPACES;
         else if (startswith(rvalue, "+")) {
                 m->namespace_flags = SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE;
                 m->namespace = strdup(rvalue);
                 if (!m->namespace)
                         return log_oom();
         } else {
                 m->namespace = strdup(rvalue);
                 if (!m->namespace)
                         return log_oom();
         }

        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many(PKGSYSCONFDIR "/netlogd.conf",
                                 CONF_PATHS_NULSTR("systemd/netlogd.conf.d"),
                                 "Network\0",
                                 config_item_perf_lookup, netlog_gperf_lookup,
                                 false, m);
}
