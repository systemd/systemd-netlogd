/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-state.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "netlog-manager.h"
#include "string-util.h"

int state_update_cursor(Manager *m) {
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

int state_load_cursor(Manager *m) {
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
