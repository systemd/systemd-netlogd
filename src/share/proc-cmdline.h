/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

int proc_cmdline(char **ret);
int parse_proc_cmdline(int (*parse_word)(const char *key, const char *value));
