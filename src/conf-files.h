/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering
  Copyright 2010-2012 Kay Sievers
***/

int conf_files_list_strv(char ***ret, const char *suffix, const char *root, const char* const* dirs);
int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, const char *dirs);
