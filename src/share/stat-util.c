/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/magic.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "dirent-util.h"
#include "fd-util.h"
#include "macro.h"
#include "missing.h"
#include "stat-util.h"
#include "string-util.h"

int is_dir(const char* path, bool follow) {
        struct stat st;
        int r;

        assert(path);

        if (follow)
                r = stat(path, &st);
        else
                r = lstat(path, &st);
        if (r < 0)
                return -errno;

        return !!S_ISDIR(st.st_mode);
}

bool null_or_empty(struct stat *st) {
        assert(st);

        if (S_ISREG(st->st_mode) && st->st_size <= 0)
                return true;

        /* We don't want to hardcode the major/minor of /dev/null,
         * hence we do a simpler "is this a device node?" check. */

        if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode))
                return true;

        return false;
}

int files_same(const char *filea, const char *fileb) {
        struct stat a, b;

        assert(filea);
        assert(fileb);

        if (stat(filea, &a) < 0)
                return -errno;

        if (stat(fileb, &b) < 0)
                return -errno;

        return a.st_dev == b.st_dev &&
               a.st_ino == b.st_ino;
}

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) {
        assert(s);
        assert_cc(sizeof(statfs_f_type_t) >= sizeof(s->f_type));

        return F_TYPE_EQUAL(s->f_type, magic_value);
}

bool is_temporary_fs(const struct statfs *s) {
    return is_fs_type(s, TMPFS_MAGIC) ||
           is_fs_type(s, RAMFS_MAGIC);
}
