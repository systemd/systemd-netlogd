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
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Failed to parse address value, ignoring: %s", rvalue);
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
                log_syntax(unit, LOG_ERR, filename, line, -r,
                           "Unrecognised Protocol '%s'", rvalue);
                return -EPROTONOSUPPORT;
        }

        m->protocol = r;
        return 0;
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_many(PKGSYSCONFDIR "/systemd-netlogd.conf",
                                 CONF_PATHS_NULSTR("systemd/systemd-netlogd.conf.d"),
                                 "Network\0",
                                 config_item_perf_lookup, netlog_gperf_lookup,
                                 false, m);
}
