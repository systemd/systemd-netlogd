/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

int conf_files_list_strv(char ***ret, const char *suffix, const char *root, const char* const* dirs);
int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, const char *dirs);
