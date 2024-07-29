/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <resolv.h>

#include "conf-parser.h"
#include "def.h"
#include "in-addr-util.h"
#include "netlog-conf.h"
#include "parse-util.h"
#include "sd-resolve.h"
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
        char *e;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);
        assert(m);

        r = socket_address_parse(&m->address, rvalue);
        if (r < 0) {
                const struct addrinfo hints = {
                        .ai_flags = AI_NUMERICSERV|AI_ADDRCONFIG,
                        .ai_socktype = SOCK_DGRAM,
                        .ai_family = socket_ipv6_is_supported() ? AF_UNSPEC : AF_INET,
                };
               uint32_t u;

                e = strchr(rvalue, ':');
                if (e) {
                        r = safe_atou(e+1, &u);
                        if (r < 0)
                                return r;

                        if (u <= 0 || u > 0xFFFF)
                                return -EINVAL;

                        m->port = u;
                        m->server_name = strndupa(rvalue, e-rvalue);
                        if (!m->server_name)
                                return log_oom();

                        log_debug("Remote server='%s' port: '%u'...", m->server_name, u);

                        /* Tell the resolver to reread /etc/resolv.conf, in
                         * case it changed. */
                        res_init();

                        log_debug("Resolving %s...", m->server_name);

                        r = sd_resolve_getaddrinfo(m->resolve, &m->resolve_query, m->server_name, NULL, &hints, manager_resolve_handler, m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create resolver: %m");

                        m->resolving = true;
                        return 0;
                }

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
        assert(m);

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
        assert(m);

        r = log_format_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, -r, "Failed to parse '%s=%s', ignoring.", lvalue, rvalue);
                return 0;
        }

        m->log_format = r;
        return 0;
}

int config_parse_tls_certificate_auth_mode(const char *unit,
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
        assert(m);

        r = certificate_auth_mode_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, -r, "Failed to parse '%s=%s', ignoring.", lvalue, rvalue);
                return 0;
        }

        m->auth_mode = r;
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
        assert(m);

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
        int r;

        assert(m);

        r = config_parse_many(PKGSYSCONFDIR "/netlogd.conf",
                             CONF_PATHS_NULSTR("systemd/netlogd.conf.d"),
                             "Network\0",
                             config_item_perf_lookup, netlog_gperf_lookup,
                             false, m);

        if (r < 0)
                return r;

        if (m->connection_retry_usec < 1 * USEC_PER_SEC) {
                log_warning("Invalid ConnectionRetrySec=. Using default value.");
                m->connection_retry_usec = DEFAULT_CONNECTION_RETRY_USEC;
        }

        return 0;
}
