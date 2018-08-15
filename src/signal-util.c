/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "macro.h"
#include "parse-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"

static int sigset_add_many_ap(sigset_t *ss, va_list ap) {
        int sig, r = 0;

        assert(ss);

        while ((sig = va_arg(ap, int)) >= 0) {

                if (sig == 0)
                        continue;

                if (sigaddset(ss, sig) < 0) {
                        if (r >= 0)
                                r = -errno;
                }
        }

        return r;
}

int sigprocmask_many(int how, sigset_t *old, ...) {
        va_list ap;
        sigset_t ss;
        int r;

        if (sigemptyset(&ss) < 0)
                return -errno;

        va_start(ap, old);
        r = sigset_add_many_ap(&ss, ap);
        va_end(ap);

        if (r < 0)
                return r;

        if (sigprocmask(how, &ss, old) < 0)
                return -errno;

        return 0;
}

static const char *const __signal_table[] = {
        [SIGHUP] = "HUP",
        [SIGINT] = "INT",
        [SIGQUIT] = "QUIT",
        [SIGILL] = "ILL",
        [SIGTRAP] = "TRAP",
        [SIGABRT] = "ABRT",
        [SIGBUS] = "BUS",
        [SIGFPE] = "FPE",
        [SIGKILL] = "KILL",
        [SIGUSR1] = "USR1",
        [SIGSEGV] = "SEGV",
        [SIGUSR2] = "USR2",
        [SIGPIPE] = "PIPE",
        [SIGALRM] = "ALRM",
        [SIGTERM] = "TERM",
#ifdef SIGSTKFLT
        [SIGSTKFLT] = "STKFLT",  /* Linux on SPARC doesn't know SIGSTKFLT */
#endif
        [SIGCHLD] = "CHLD",
        [SIGCONT] = "CONT",
        [SIGSTOP] = "STOP",
        [SIGTSTP] = "TSTP",
        [SIGTTIN] = "TTIN",
        [SIGTTOU] = "TTOU",
        [SIGURG] = "URG",
        [SIGXCPU] = "XCPU",
        [SIGXFSZ] = "XFSZ",
        [SIGVTALRM] = "VTALRM",
        [SIGPROF] = "PROF",
        [SIGWINCH] = "WINCH",
        [SIGIO] = "IO",
        [SIGPWR] = "PWR",
        [SIGSYS] = "SYS"
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(__signal, int);

const char *signal_to_string(int signo) {
        static thread_local char buf[sizeof("RTMIN+")-1 + DECIMAL_STR_MAX(int) + 1];
        const char *name;

        name = __signal_to_string(signo);
        if (name)
                return name;

        if (signo >= SIGRTMIN && signo <= SIGRTMAX)
                xsprintf(buf, "RTMIN+%d", signo - SIGRTMIN);
        else
                xsprintf(buf, "%d", signo);

        return buf;
}

int signal_from_string(const char *s) {
        int signo;
        int offset = 0;
        unsigned u;

        signo = __signal_from_string(s);
        if (signo > 0)
                return signo;

        if (startswith(s, "RTMIN+")) {
                s += 6;
                offset = SIGRTMIN;
        }
        if (safe_atou(s, &u) >= 0) {
                signo = (int) u + offset;
                if (SIGNAL_VALID(signo))
                        return signo;
        }
        return -EINVAL;
}

void nop_signal_handler(int sig) {
        /* nothing here */
}
