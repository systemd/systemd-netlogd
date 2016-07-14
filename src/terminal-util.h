#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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
