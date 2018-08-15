/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <signal.h>

#include "macro.h"

int sigprocmask_many(int how, sigset_t *old, ...);

const char *signal_to_string(int i) _const_;
int signal_from_string(const char *s) _pure_;

void nop_signal_handler(int sig);

static inline void block_signals_reset(sigset_t *ss) {
        assert_se(sigprocmask(SIG_SETMASK, ss, NULL) >= 0);
}

#define BLOCK_SIGNALS(...)                                                        \
        _cleanup_(block_signals_reset) _unused_ sigset_t _saved_sigset = ({       \
                sigset_t t;                                                       \
                assert_se(sigprocmask_many(SIG_BLOCK, &t, __VA_ARGS__, -1) >= 0); \
                t;                                                                \
        })

static inline bool SIGNAL_VALID(int signo) {
        return signo > 0 && signo < _NSIG;
}
