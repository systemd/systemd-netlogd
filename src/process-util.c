/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/oom.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "ioprio.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "process-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "user-util.h"
#include "util.h"

int get_process_comm(pid_t pid, char **name) {
        const char *p;
        int r;

        assert(name);
        assert(pid >= 0);

        p = procfs_file_alloca(pid, "comm");

        r = read_one_line_file(p, name);
        if (r == -ENOENT)
                return -ESRCH;

        return r;
}

int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        bool space = false;
        char *r = NULL, *k;
        const char *p;
        int c;

        assert(line);
        assert(pid >= 0);

        /* Retrieves a process' command line. Replaces unprintable characters while doing so by whitespace (coalescing
         * multiple sequential ones into one). If max_length is != 0 will return a string of the specified size at most
         * (the trailing NUL byte does count towards the length here!), abbreviated with a "..." ellipsis. If
         * comm_fallback is true and the process has no command line set (the case for kernel threads), or has a
         * command line that resolves to the empty string will return the "comm" name of the process instead.
         *
         * Returns -ESRCH if the process doesn't exist, and -ENOENT if the process has no command line (and
         * comm_fallback is false). */

        p = procfs_file_alloca(pid, "cmdline");

        f = fopen(p, "re");
        if (!f) {
                if (errno == ENOENT)
                        return -ESRCH;
                return -errno;
        }

        if (max_length == 1) {

                /* If there's only room for one byte, return the empty string */
                r = new0(char, 1);
                if (!r)
                        return -ENOMEM;

                *line = r;
                return 0;

        } else if (max_length == 0) {
                size_t len = 0, allocated = 0;

                while ((c = getc(f)) != EOF) {

                        if (!GREEDY_REALLOC(r, allocated, len+3)) {
                                free(r);
                                return -ENOMEM;
                        }

                        if (isprint(c)) {
                                if (space) {
                                        r[len++] = ' ';
                                        space = false;
                                }

                                r[len++] = c;
                        } else if (len > 0)
                                space = true;
               }

                if (len > 0)
                        r[len] = 0;
                else
                        r = mfree(r);

        } else {
                bool dotdotdot = false;
                size_t left;

                r = new(char, max_length);
                if (!r)
                        return -ENOMEM;

                k = r;
                left = max_length;
                while ((c = getc(f)) != EOF) {

                        if (isprint(c)) {

                                if (space) {
                                        if (left <= 2) {
                                                dotdotdot = true;
                                                break;
                                        }

                                        *(k++) = ' ';
                                        left--;
                                        space = false;
                                }

                                if (left <= 1) {
                                        dotdotdot = true;
                                        break;
                                }

                                *(k++) = (char) c;
                                left--;
                        }  else if (k > r)
                                space = true;
                }

                if (dotdotdot) {
                        if (max_length <= 4) {
                                k = r;
                                left = max_length;
                        } else {
                                k = r + max_length - 4;
                                left = 4;

                                /* Eat up final spaces */
                                while (k > r && isspace(k[-1])) {
                                        k--;
                                        left++;
                                }
                        }

                        strncpy(k, "...", left-1);
                        k[left-1] = 0;
                } else
                        *k = 0;
        }

        /* Kernel threads have no argv[] */
        if (isempty(r)) {
                _cleanup_free_ char *t = NULL;
                int h;

                free(r);

                if (!comm_fallback)
                        return -ENOENT;

                h = get_process_comm(pid, &t);
                if (h < 0)
                        return h;

                if (max_length == 0)
                        r = strjoin("[", t, "]", NULL);
                else {
                        size_t l;

                        l = strlen(t);

                        if (l + 3 <= max_length)
                                r = strjoin("[", t, "]", NULL);
                        else if (max_length <= 6) {

                                r = new(char, max_length);
                                if (!r)
                                        return -ENOMEM;

                                memcpy(r, "[...]", max_length-1);
                                r[max_length-1] = 0;
                        } else {
                                char *e;

                                t[max_length - 6] = 0;

                                /* Chop off final spaces */
                                e = strchr(t, 0);
                                while (e > t && isspace(e[-1]))
                                        e--;
                                *e = 0;

                                r = strjoin("[", t, "...]", NULL);
                        }
                }
                if (!r)
                        return -ENOMEM;
        }

        *line = r;
        return 0;
}

int getenv_for_pid(pid_t pid, const char *field, char **_value) {
        _cleanup_fclose_ FILE *f = NULL;
        char *value = NULL;
        int r;
        bool done = false;
        size_t l;
        const char *path;

        assert(pid >= 0);
        assert(field);
        assert(_value);

        path = procfs_file_alloca(pid, "environ");

        f = fopen(path, "re");
        if (!f) {
                if (errno == ENOENT)
                        return -ESRCH;
                return -errno;
        }

        l = strlen(field);
        r = 0;

        do {
                char line[LINE_MAX];
                unsigned i;

                for (i = 0; i < sizeof(line)-1; i++) {
                        int c;

                        c = getc(f);
                        if (_unlikely_(c == EOF)) {
                                done = true;
                                break;
                        } else if (c == 0)
                                break;

                        line[i] = c;
                }
                line[i] = 0;

                if (memcmp(line, field, l) == 0 && line[l] == '=') {
                        value = strdup(line + l + 1);
                        if (!value)
                                return -ENOMEM;

                        r = 1;
                        break;
                }

        } while (!done);

        *_value = value;
        return r;
}

bool is_main_thread(void) {
        static thread_local int cached = 0;

        if (_unlikely_(cached == 0))
                cached = getpid() == gettid() ? 1 : -1;

        return cached > 0;
}

static const char *const sigchld_code_table[] = {
        [CLD_EXITED] = "exited",
        [CLD_KILLED] = "killed",
        [CLD_DUMPED] = "dumped",
        [CLD_TRAPPED] = "trapped",
        [CLD_STOPPED] = "stopped",
        [CLD_CONTINUED] = "continued",
};

DEFINE_STRING_TABLE_LOOKUP(sigchld_code, int);

static const char* const sched_policy_table[] = {
        [SCHED_OTHER] = "other",
        [SCHED_BATCH] = "batch",
        [SCHED_IDLE] = "idle",
        [SCHED_FIFO] = "fifo",
        [SCHED_RR] = "rr"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(sched_policy, int, INT_MAX);
