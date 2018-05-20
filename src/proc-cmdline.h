/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

int proc_cmdline(char **ret);
int parse_proc_cmdline(int (*parse_word)(const char *key, const char *value));
