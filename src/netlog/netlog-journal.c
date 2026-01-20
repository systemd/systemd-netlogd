/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-journal.h"

#include <systemd/sd-journal.h>

#include "alloc-util.h"
#include "netlog-manager.h"
#include "netlog-state.h"
#include "parse-util.h"

/* Default severity LOG_NOTICE */
#define JOURNAL_DEFAULT_SEVERITY LOG_PRI(LOG_NOTICE)

/* Default facility LOG_USER */
#define JOURNAL_DEFAULT_FACILITY LOG_FAC(LOG_USER)

#define JOURNAL_FOREACH_DATA_RETVAL(j, data, l, retval)                     \
        for (sd_journal_restart_data(j); ((retval) = sd_journal_enumerate_data((j), &(data), &(l))) > 0; )

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

static int parse_journal_fields(Manager *m,
                                char **message,
                                char **identifier,
                                char **hostname,
                                char **pid,
                                char **facility,
                                char **priority,
                                char **structured_data,
                                char **msgid) {
        const void *data;
        size_t length;
        int r;
        size_t hostname_len = 0, identifier_len = 0, message_len = 0, priority_len = 0, facility_len = 0,
                structured_data_len = 0, msgid_len = 0, pid_len = 0;
        const ParseFieldVec fields[] = {
                PARSE_FIELD_VEC_ENTRY("_PID=",                        pid,               &pid_len              ),
                PARSE_FIELD_VEC_ENTRY("MESSAGE=",                     message,           &message_len          ),
                PARSE_FIELD_VEC_ENTRY("PRIORITY=",                    priority,          &priority_len         ),
                PARSE_FIELD_VEC_ENTRY("_HOSTNAME=",                   hostname,          &hostname_len         ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_FACILITY=",             facility,          &facility_len         ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_IDENTIFIER=",           identifier,        &identifier_len       ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_STRUCTURED_DATA=",      structured_data,   &structured_data_len  ),
                PARSE_FIELD_VEC_ENTRY("SYSLOG_MSGID",                 msgid,             &msgid_len            ),
        };

        JOURNAL_FOREACH_DATA_RETVAL(m->journal, data, length, r) {
                r = parse_fieldv(data, length, fields, ELEMENTSOF(fields));
                if (r < 0)
                        return r;
        }

        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_debug_errno(r, "Skipping message we can't read: %m");
                return 0;
        }

        return r;
}

static int parse_syslog_severity(Manager *m, const char *priority, unsigned *sev) {
        int r;

        assert(sev);

        if (!priority)
                return 0;

        r = safe_atou(priority, sev);
        if (r < 0) {
                log_debug("Failed to parse syslog priority: %s", priority);
                return r;
        }

        if (*sev < _SYSLOG_LEVEL_MAX && ((UINT8_C(1) << *sev) & m->excluded_syslog_levels)) {
                log_debug("Skipping message with excluded syslog level %s.", syslog_level_to_string(*sev));
                return 1; /* filtered */
        }

        if (*sev > LOG_DEBUG)
                *sev = JOURNAL_DEFAULT_SEVERITY;

        return 0;
}

static int parse_syslog_facility(Manager *m, const char *facility, unsigned *fac) {
        int r;

        assert(fac);

        if (!facility)
                return 0;

        r = safe_atou(facility, fac);
        if (r < 0) {
                log_debug("Failed to parse syslog facility: %s", facility);
                return r;
        }

        if (*fac < _SYSLOG_FACILITY_MAX && ((UINT32_C(1) << *fac) & m->excluded_syslog_facilities)) {
                log_debug("Skipping message with excluded syslog facility %s.", syslog_facility_to_string(*fac));
                return 1; /* filtered */
        }

        if (*fac >= LOG_NFACILITIES)
                *fac = JOURNAL_DEFAULT_FACILITY;

        return 0;
}

static int journal_read_input(Manager *m) {
        _cleanup_free_ char *facility = NULL, *identifier = NULL, *priority = NULL, *message = NULL, *pid = NULL,
                *hostname = NULL, *structured_data = NULL, *msgid = NULL, *cursor = NULL;
        unsigned sev = JOURNAL_DEFAULT_SEVERITY;
        unsigned fac = JOURNAL_DEFAULT_FACILITY;
        struct timeval tv, *tvp = NULL;
        usec_t realtime;
        int r;

        assert(m);
        assert(m->journal);

        r = sd_journal_get_cursor(m->journal, &cursor);
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        log_debug("Reading from journal cursor=%s", cursor);

        r = parse_journal_fields(m, &message, &identifier, &hostname, &pid, &facility, &priority, &structured_data, &msgid);
        if (r < 0)
                return log_error_errno(r, "Failed to get journal fields: %m");
        if (r == 0)
                return 0;

        if (!message) {
                log_debug("Skipping message without MESSAGE= field.");
                return 0;
        }

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

        r = parse_syslog_facility(m, facility, &fac);
        if (r > 0) /* filtered */
                return 0;

        r = parse_syslog_severity(m, priority, &sev);
        if (r > 0) /* filtered */
                return 0;

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

static int journal_process_input(Manager *m) {
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

                r = journal_read_input(m);
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

        return state_update_cursor(m);
}

int journal_event_handler(sd_event_source *event, int fd, uint32_t revents, void *userp) {
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

        return journal_process_input(m);
}

void journal_close_input(Manager *m) {
        assert(m);

        if (m->journal) {
                log_debug("Closing journal input.");

                sd_journal_close(m->journal);
                m->journal = NULL;
                m->journal_watch_fd = -1;
        }
}

static int journal_open(Manager *m) {
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

int journal_monitor_listen(Manager *m) {
        int r, events;

        assert(m);

        r = journal_open(m);
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
                            events, journal_event_handler, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register input event: %m");

        /* ignore failure */
        if (!m->last_cursor)
                (void) state_load_cursor(m);

        if (m->last_cursor) {
                r = sd_journal_seek_cursor(m->journal, m->last_cursor);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to cursor %s: %m", m->last_cursor);
        }

        return 0;
}
