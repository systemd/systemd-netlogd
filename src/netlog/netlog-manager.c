/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <systemd/sd-daemon.h>

#include "capability-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "conf-parser.h"
#include "fd-util.h"
#include "netlog-manager.h"
#include "network-util.h"
#include "parse-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

/* Default severity LOG_NOTICE */
#define JOURNAL_DEFAULT_SEVERITY LOG_PRI(LOG_NOTICE)

/* Default facility LOG_USER */
#define JOURNAL_DEFAULT_FACILITY LOG_FAC(LOG_USER)

#define RATELIMIT_INTERVAL_USEC (10*USEC_PER_SEC)
#define RATELIMIT_BURST 10

#define JOURNAL_FOREACH_DATA_RETVAL(j, data, l, retval)                     \
        for (sd_journal_restart_data(j); ((retval) = sd_journal_enumerate_data((j), &(data), &(l))) > 0; )

static const char *const protocol_table[_SYSLOG_TRANSMISSION_PROTOCOL_MAX] = {
        [SYSLOG_TRANSMISSION_PROTOCOL_UDP]  = "udp",
        [SYSLOG_TRANSMISSION_PROTOCOL_TCP]  = "tcp",
        [SYSLOG_TRANSMISSION_PROTOCOL_DTLS] = "dtls",
        [SYSLOG_TRANSMISSION_PROTOCOL_TLS]  = "tls",
};

DEFINE_STRING_TABLE_LOOKUP(protocol, SysLogTransmissionProtocol);

static const char *const log_format_table[_SYSLOG_TRANSMISSION_LOG_FORMAT_MAX] = {
        [SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424] = "rfc5424",
        [SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5425] = "rfc5425",
        [SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_3339] = "rfc3339",
};

DEFINE_STRING_TABLE_LOOKUP(log_format, SysLogTransmissionLogFormat);

static const char *const syslog_facility_table[_SYSLOG_FACILITY_MAX] = {
        [SYSLOG_FACILITY_KERN]         = "kern",
        [SYSLOG_FACILITY_USER]         = "user",
        [SYSLOG_FACILITY_MAIL]         = "mail",
        [SYSLOG_FACILITY_DAEMON]       = "daemon",
        [SYSLOG_FACILITY_AUTH]         = "auth",
        [SYSLOG_FACILITY_SYSLOG]       = "syslog",
        [SYSLOG_FACILITY_LPR]          = "lpr",
        [SYSLOG_FACILITY_NEWS]         = "news",
        [SYSLOG_FACILITY_UUCP]         = "uucp",
        [SYSLOG_FACILITY_CRON]         = "cron",
        [SYSLOG_FACILITY_AUTHPRIV]     = "authpriv",
        [SYSLOG_FACILITY_FTP]          = "ftp",
        [SYSLOG_FACILITY_NTP]          = "ntp",
        [SYSLOG_FACILITY_SECURITY]     = "security",
        [SYSLOG_FACILITY_CONSOLE]      = "console",
        [SYSLOG_FACILITY_SOLARIS_CRON] = "solaris-cron",
        [SYSLOG_FACILITY_LOCAL0]       = "local0",
        [SYSLOG_FACILITY_LOCAL1]       = "local1",
        [SYSLOG_FACILITY_LOCAL2]       = "local2",
        [SYSLOG_FACILITY_LOCAL3]       = "local3",
        [SYSLOG_FACILITY_LOCAL4]       = "local4",
        [SYSLOG_FACILITY_LOCAL5]       = "local5",
        [SYSLOG_FACILITY_LOCAL6]       = "local6",
        [SYSLOG_FACILITY_LOCAL7]       = "local7",
};

DEFINE_STRING_TABLE_LOOKUP(syslog_facility, SysLogFacility);

static const char *const syslog_level_table[_SYSLOG_LEVEL_MAX] = {
        [SYSLOG_LEVEL_EMERGENCY]     = "emerg",
        [SYSLOG_LEVEL_ALERT]         = "alert",
        [SYSLOG_LEVEL_CRITICAL]      = "crit",
        [SYSLOG_LEVEL_ERROR]         = "err",
        [SYSLOG_LEVEL_WARNING]       = "warning",
        [SYSLOG_LEVEL_NOTICE]        = "notice",
        [SYSLOG_LEVEL_INFORMATIONAL] = "info",
        [SYSLOG_LEVEL_DEBUG]         = "debug",
};

DEFINE_STRING_TABLE_LOOKUP(syslog_level, SysLogLevel);

typedef struct ParseFieldVec {
        const char *field;
        size_t field_len;
        char **target;
        size_t *target_len;
} ParseFieldVec;

#define PARSE_FIELD_VEC_ENTRY(_field, _target, _target_len) {           \
                .field = (_field),                                      \
                .field_len = strlen(_field),                            \
                .target = (_target),                                    \
                .target_len = (_target_len)                             \
        }

static int parse_field(
                const void *data,
                size_t length,
                const char *field,
                size_t field_len,
                char **target,
                size_t *target_len) {

        size_t nl;
        char *buf;

        assert(data);
        assert(field);
        assert(target);

        if (length < field_len)
                return 0;

        if (memcmp(data, field, field_len))
                return 0;

        nl = length - field_len;

        buf = newdup_suffix0(char, (const char*) data + field_len, nl);
        if (!buf)
                return log_oom();

        free_and_replace(*target, buf);

        if (target_len)
                *target_len = nl;

        return 1;
}

static int parse_fieldv(
                const void *data,
                size_t length,
                const ParseFieldVec *fields,
                size_t n_fields) {

        int r;

        for (size_t i = 0; i < n_fields; i++) {
                const ParseFieldVec *f = &fields[i];

                r = parse_field(data, length, f->field, f->field_len, f->target, f->target_len);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;
        }

        return 0;
}

static int manager_read_journal_input(Manager *m) {
        _cleanup_free_ char *facility = NULL, *identifier = NULL, *priority = NULL, *message = NULL, *pid = NULL,
                *hostname = NULL, *structured_data = NULL, *msgid = NULL, *cursor = NULL;
        size_t hostname_len = 0, identifier_len = 0, message_len = 0, priority_len = 0, facility_len = 0,
                structured_data_len = 0, msgid_len = 0, pid_len = 0;
        unsigned sev = JOURNAL_DEFAULT_SEVERITY;
        unsigned fac = JOURNAL_DEFAULT_FACILITY;
        struct timeval tv, *tvp = NULL;
        const void *data;
        usec_t realtime;
        size_t length;
        int r;
        const ParseFieldVec fields[] = {
                PARSE_FIELD_VEC_ENTRY("_PID=",                        &pid,               &pid_len              ),
                PARSE_FIELD_VEC_ENTRY("MESSAGE=",                     &message,           &message_len          ),
                PARSE_FIELD_VEC_ENTRY("PRIORITY=",                    &priority,          &priority_len         ),
                PARSE_FIELD_VEC_ENTRY("_HOSTNAME=",                   &hostname,          &hostname_len         ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_FACILITY=",             &facility,          &facility_len         ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_IDENTIFIER=",           &identifier,        &identifier_len       ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_STRUCTURED_DATA=",      &structured_data,   &structured_data_len  ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_MSGID",                 &msgid,             &msgid_len            ),
        };

        assert(m);
        assert(m->journal);

        r = sd_journal_get_cursor(m->journal, &cursor);
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        log_debug("Reading from journal cursor=%s", cursor);

        JOURNAL_FOREACH_DATA_RETVAL(m->journal, data, length, r) {
                r = parse_fieldv(data, length, fields, ELEMENTSOF(fields));
                if (r < 0)
                        return r;
        }

        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_debug_errno(r, "Skipping message we can't read: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get journal fields: %m");

        if (!message) {
                log_debug("Skipping message without MESSAGE= field.");
                return 0;
        } else
                log_debug("Received from journal MESSAGE='%s'", message);

        r = sd_journal_get_realtime_usec(m->journal, &realtime);
        if (r < 0)
                log_warning_errno(r, "Failed to rerieve realtime from journal: %m");
        else {
                tv = (struct timeval) {
                        .tv_sec = realtime / USEC_PER_SEC,
                        .tv_usec = realtime % USEC_PER_SEC,
                };
                tvp = &tv;
        }

        if (facility) {
                r = safe_atou(facility, &fac);
                if (r < 0)
                        log_debug("Failed to parse syslog facility: %s", facility);
                else if (fac < _SYSLOG_FACILITY_MAX && ((UINT32_C(1) << fac) & m->excluded_syslog_facilities)) {
                        log_debug("Skipping message with excluded syslog facility %s.", syslog_facility_to_string(fac));
                        return 0;
                }

                if (fac >= LOG_NFACILITIES)
                        fac = JOURNAL_DEFAULT_FACILITY;
        }

        if (priority) {
                r = safe_atou(priority, &sev);
                if (r < 0)
                        log_debug("Failed to parse syslog priority: %s", priority);
                else if (sev < _SYSLOG_LEVEL_MAX && ((UINT8_C(1) << sev) & m->excluded_syslog_levels)) {
                        log_debug("Skipping message with excluded syslog level %s.", syslog_level_to_string(sev));
                        return 0;
                }

                if (sev > LOG_DEBUG)
                        sev = JOURNAL_DEFAULT_SEVERITY;
        }

        return manager_push_to_network(m,
                                       sev,
                                       fac,
                                       identifier,
                                       message, hostname,
                                       pid,
                                       tvp,
                                       structured_data,
                                       m->syslog_msgid ? msgid : NULL);
}

static int update_cursor_state(Manager *m) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        if (!m->state_file || !m->last_cursor)
                return 0;

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        r = fchmod(fileno(f), 0644);
        if (r < 0)
                log_warning_errno(errno, "Failed to set mode of state %s: %m", m->state_file);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "LAST_CURSOR=%s\n",
                m->last_cursor);

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        if (rename(temp_path, m->state_file) < 0) {
                r = -errno;
                goto finish;
        }

 finish:
        if (r < 0)
                log_error_errno(r, "Failed to save state %s: %m", m->state_file);

        if (temp_path)
                (void) unlink(temp_path);

        return r;
}

static int load_cursor_state(Manager *m) {
        int r;

        assert(m);

        if (!m->state_file)
                return 0;

        r = parse_env_file(m->state_file, NEWLINE, "LAST_CURSOR", &m->last_cursor, NULL);
        if (r < 0 && r != -ENOENT)
                return r;

        log_debug("Last cursor was %s.", m->last_cursor ? m->last_cursor : "not available");

        return 0;
}

static int process_journal_input(Manager *m) {
        _cleanup_free_ char *cursor = NULL;
        int r;

        assert(m);
        assert(m->journal);

        for (;;) {
                r = sd_journal_next(m->journal);
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry: %m");

                if (r == 0)
                        break;

                r = manager_read_journal_input(m);
                if (r < 0) {
                        /* Can't send the message. Seek one entry back. */
                        r = sd_journal_previous(m->journal);
                        if (r < 0)
                                log_error_errno(r, "Failed to iterate through journal: %m");

                        break;
                }
        }

        r = sd_journal_get_cursor(m->journal, &cursor);
        if (r < 0) {
                log_error_errno(r, "Failed to get cursor: %m");
                cursor = mfree(cursor);
        }

        free(m->last_cursor);
        m->last_cursor = cursor;
        cursor = NULL;

        return update_cursor_state(m);
}

static int manager_journal_event_handler(sd_event_source *event, int fd, uint32_t revents, void *userp) {
        Manager *m = userp;
        int r;

        assert(m);
        assert(m->journal);
        assert(m->journal_watch_fd == fd);

        if (revents & EPOLLHUP) {
                log_debug("Received HUP");
                return 0;
        }

        if (!(revents & EPOLLIN)) {
                log_warning("Unexpected poll event %"PRIu32".", revents);
                return -EINVAL;
        }

        r = sd_journal_process(m->journal);
        if (r < 0) {
                log_error_errno(r, "Failed to process journal: %m");
                manager_disconnect(m);
                return r;
        }

        if (r == SD_JOURNAL_NOP)
                return 0;

        return process_journal_input(m);
}

static void close_journal_input(Manager *m) {
        assert(m);

        if (m->journal) {
                log_debug("Closing journal input.");

                sd_journal_close(m->journal);
                m->journal = NULL;
                m->journal_watch_fd = -1;
        }
}

static int manager_signal_event_handler(sd_event_source *event, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = userdata;

        assert(m);

        log_received_signal(LOG_INFO, si);

        manager_disconnect(m);

        sd_event_exit(m->event, 0);

        return 0;
}

static int open_journal(Manager *m) {
        int r;

        assert(m);

        if (m->dir)
                r = sd_journal_open_directory(&m->journal, m->dir, 0);
        else if (m->namespace)
                r = sd_journal_open_namespace(&m->journal, m->namespace, SD_JOURNAL_LOCAL_ONLY | m->namespace_flags);
        else
                r = sd_journal_open(&m->journal, SD_JOURNAL_LOCAL_ONLY);

        if (r < 0)
                log_error_errno(r, "Failed to open %s: %m", m->dir ?: m->namespace ? "namespace journal" : "journal");

        return r;
}

static int manager_journal_monitor_listen(Manager *m) {
        int r, events;

        assert(m);

        r = open_journal(m);
        if (r < 0)
                return r;

        r = sd_journal_set_data_threshold(m->journal, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to set journal data field size threshold");

        m->journal_watch_fd = sd_journal_get_fd(m->journal);
        if (m->journal_watch_fd  < 0)
                return log_error_errno(m->journal_watch_fd, "Failed to get journal fd: %m");

        events = sd_journal_get_events(m->journal);

        r = sd_event_add_io(m->event, &m->event_journal_input, m->journal_watch_fd,
                            events, manager_journal_event_handler, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register input event: %m");

        /* ignore failure */
        if (!m->last_cursor)
                (void) load_cursor_state(m);

        if (m->last_cursor) {
                r = sd_journal_seek_cursor(m->journal, m->last_cursor);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to cursor %s: %m", m->last_cursor);
        }

        return 0;
}

static int manager_retry_connect(sd_event_source *source, usec_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return manager_connect(m);
}

int manager_connect(Manager *m) {
        int r;

        assert(m);

        if (m->resolving)
                return 0;

        manager_disconnect(m);

        log_debug("Connecting network ...");

        m->event_retry = sd_event_source_unref(m->event_retry);
        if (!ratelimit_below(&m->ratelimit)) {
                log_debug("Delaying attempts to contact servers.");

                r = sd_event_add_time_relative(m->event, &m->event_retry, CLOCK_BOOTTIME, m->connection_retry_usec,
                                               0, manager_retry_connect, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to create retry timer: %m");

                return 0;
        }

        switch (m->protocol) {
                case SYSLOG_TRANSMISSION_PROTOCOL_DTLS:
                        r = dtls_connect(m->dtls, &m->address);
                        break;
                case SYSLOG_TRANSMISSION_PROTOCOL_TLS:
                        r = tls_connect(m->tls, &m->address);
                        break;
                default:
                        r = manager_open_network_socket(m);
                        break;
        }
        if (r < 0) {
                log_error_errno(r, "Failed to create network socket: %m");
                return manager_connect(m);
        }
        r = manager_journal_monitor_listen(m);
        if (r < 0)
                return log_error_errno(r, "Failed to monitor journal: %m");

        return 0;
}

void manager_disconnect(Manager *m) {
        assert(m);

        log_debug("Disconnecting network ...");

        m->resolve_query = sd_resolve_query_unref(m->resolve_query);

        manager_close_network_socket(m);

        dtls_disconnect(m->dtls);
        tls_disconnect(m->tls);

        m->event_journal_input = sd_event_source_disable_unref(m->event_journal_input);
        close_journal_input(m);

        sd_notifyf(false, "STATUS=Idle.");
}

int manager_resolve_handler(sd_resolve_query *q, int ret, const struct addrinfo *ai, void *userdata) {
        Manager *m = userdata;

        assert(q);
        assert(m);
        assert(m->server_name);

        log_debug("Resolve %s: %s", m->server_name, gai_strerror(ret));

        m->resolve_query = sd_resolve_query_unref(m->resolve_query);

        if (ret != 0) {
                log_debug("Failed to resolve %s: %s", m->server_name, gai_strerror(ret));

                /* Try next host */
                return manager_connect(m);
        }

        for (; ai; ai = ai->ai_next) {
                _cleanup_free_ char *pretty = NULL;

                assert(ai->ai_addr);
                assert(ai->ai_addrlen >= offsetof(struct sockaddr, sa_data));

                if (!IN_SET(ai->ai_addr->sa_family, AF_INET, AF_INET6)) {
                        log_warning("Unsuitable address protocol for %s", m->server_name);
                        continue;
                }

                memcpy(&m->address.sockaddr, (const union sockaddr_union*) ai->ai_addr, ai->ai_addrlen);

                if (ai->ai_addr->sa_family == AF_INET6)
                        m->address.sockaddr.in6.sin6_port = htobe16((uint16_t) m->port);
                else
                        m->address.sockaddr.in.sin_port = htobe16((uint16_t) m->port);

                sockaddr_pretty(&m->address.sockaddr.sa, ai->ai_addrlen, true, true, &pretty);

                log_debug("Resolved address %s for %s.", pretty, m->server_name);

                /* take the first one */
                break;
        }

        if (!IN_SET(m->address.sockaddr.sa.sa_family, AF_INET, AF_INET6)) {
                log_error("Failed to find suitable address for host %s.", m->server_name);

                /* Try next host */
                return manager_connect(m);
        }

        m->resolving = false;
        return manager_connect(m);
}

static int manager_network_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        bool connected, online;
        int r;

        assert(m);

        sd_network_monitor_flush(m->network_monitor);

        /* check if the machine is online */
        online = network_is_online();

        /* check if the socket is currently open*/
        connected = m->socket >= 0;

        if (connected && !online) {
                log_info("No network connectivity, watching for changes.");
                manager_disconnect(m);

        } else if (!connected && online) {
                log_info("Network configuration changed, trying to establish connection.");

                r = manager_connect(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_network_monitor_listen(Manager *m) {
        int r, fd, events;

        assert(m);

        r = sd_network_monitor_new(&m->network_monitor, NULL);
        if (r < 0)
                return r;

        fd = sd_network_monitor_get_fd(m->network_monitor);
        if (fd < 0)
                return fd;

        events = sd_network_monitor_get_events(m->network_monitor);
        if (events < 0)
                return events;

        r = sd_event_add_io(m->event, &m->network_event_source, fd, events, manager_network_event_handler, m);
        if (r < 0)
                return r;

        return 0;
}

void manager_free(Manager *m) {
        if (!m)
                return;

        manager_disconnect(m);

        free(m->dtls);
        free(m->tls);
        free(m->server_cert);

        free(m->server_name);

        free(m->last_cursor);

        free(m->state_file);
        free(m->dir);
        free(m->namespace);

        sd_resolve_unref(m->resolve);

        sd_event_source_unref(m->network_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_event_source_unref(m->event_retry);
        sd_event_unref(m->event);
        free(m);
}

int manager_new(const char *state_file, const char *cursor, Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return log_oom();

        *m = (Manager) {
                .socket = -1,
                .journal_watch_fd = -1,
                .state_file = strdup(state_file),
                .protocol = SYSLOG_TRANSMISSION_PROTOCOL_UDP,
                .log_format = SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424,
                .auth_mode = OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY,
                .connection_retry_usec = DEFAULT_CONNECTION_RETRY_USEC,
                .ratelimit = (const RateLimit) {
                        RATELIMIT_INTERVAL_USEC,
                        RATELIMIT_BURST
                },
            };

        r = socket_address_parse(&m->address, "239.0.0.1:6000");
        assert(r == 0);

        if (!m->state_file)
                return log_oom();

        if (cursor) {
                m->last_cursor = strdup(cursor);
                if (!m->last_cursor)
                        return log_oom();
        }

        r = sd_event_default(&m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);
        r = sd_event_add_signal(m->event, NULL, SIGTERM, manager_signal_event_handler, m);
        if (r < 0)
                log_warning_errno(r, "Failed to add SIGTERM event handler: %m");
        r = sd_event_add_signal(m->event, NULL, SIGINT, manager_signal_event_handler, m);
        if (r < 0)
                log_warning_errno(r, "Failed to add SIGTERM event handler: %m");

        sd_event_set_watchdog(m->event, true);

        r = sd_resolve_default(&m->resolve);
        if (r < 0)
                return r;

        r = sd_resolve_attach_event(m->resolve, m->event, 0);
        if (r < 0)
                return r;

        r = manager_network_monitor_listen(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}
