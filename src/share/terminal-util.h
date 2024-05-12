/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

#define ANSI_RED "\x1B[0;31m"
#define ANSI_GREEN "\x1B[0;32m"
#define ANSI_UNDERLINE "\x1B[0;4m"
#define ANSI_HIGHLIGHT "\x1B[0;1;39m"
#define ANSI_HIGHLIGHT_RED "\x1B[0;1;31m"
#define ANSI_HIGHLIGHT_GREEN "\x1B[0;1;32m"
#define ANSI_HIGHLIGHT_YELLOW "\x1B[0;1;33m"
#define ANSI_HIGHLIGHT_BLUE "\x1B[0;1;34m"
#define ANSI_HIGHLIGHT_UNDERLINE "\x1B[0;1;4m"
#define ANSI_NORMAL "\x1B[0m"

#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

/* Set cursor to top left corner and clear screen */
#define ANSI_HOME_CLEAR "\x1B[H\x1B[2J"

int open_terminal(const char *name, int mode);

bool on_tty(void);
bool terminal_is_dumb(void);
bool colors_enabled(void);

static inline const char *ansi_underline(void) {
        return colors_enabled() ? ANSI_UNDERLINE : "";
}

static inline const char *ansi_highlight(void) {
        return colors_enabled() ? ANSI_HIGHLIGHT : "";
}

static inline const char *ansi_highlight_underline(void) {
        return colors_enabled() ? ANSI_HIGHLIGHT_UNDERLINE : "";
}

static inline const char *ansi_highlight_red(void) {
        return colors_enabled() ? ANSI_HIGHLIGHT_RED : "";
}

static inline const char *ansi_highlight_green(void) {
        return colors_enabled() ? ANSI_HIGHLIGHT_GREEN : "";
}

static inline const char *ansi_highlight_yellow(void) {
        return colors_enabled() ? ANSI_HIGHLIGHT_YELLOW : "";
}

static inline const char *ansi_highlight_blue(void) {
        return colors_enabled() ? ANSI_HIGHLIGHT_BLUE : "";
}

static inline const char *ansi_normal(void) {
        return colors_enabled() ? ANSI_NORMAL : "";
}

int get_ctty_devnr(pid_t pid, dev_t *d);
