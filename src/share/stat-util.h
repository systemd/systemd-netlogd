#pragma once
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "macro.h"

int is_dir(const char *path, bool follow);

bool null_or_empty(const struct stat *st) _pure_;

int files_same(const char *filea, const char *fileb);

/* The .f_type field of struct statfs is really weird defined on
 * different archs. Let's give its type a name. */
typedef typeof(((struct statfs*)NULL)->f_type) statfs_f_type_t;

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value);

bool is_temporary_fs(const struct statfs *s) _pure_;

/* Because statfs.t_type can be int on some architectures, we have to cast
 * the const magic to the type, otherwise the compiler warns about
 * signed/unsigned comparison, because the magic can be 32 bit unsigned.
 */
#define F_TYPE_EQUAL(a, b) (a == (typeof(a)) b)
