/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "stat-util.h"
#include "user-util.h"

int mkdir_safe_internal(const char *path, mode_t mode, uid_t uid, gid_t gid, mkdir_func_t _mkdir) {
        struct stat st;

        if (_mkdir(path, mode) >= 0)
                if (chmod_and_chown(path, mode, uid, gid) < 0)
                        return -errno;

        if (lstat(path, &st) < 0)
                return -errno;

        if ((st.st_mode & 0007) > (mode & 0007) ||
            (st.st_mode & 0070) > (mode & 0070) ||
            (st.st_mode & 0700) > (mode & 0700) ||
            (uid != UID_INVALID && st.st_uid != uid) ||
            (gid != GID_INVALID && st.st_gid != gid) ||
            !S_ISDIR(st.st_mode))
                return -EEXIST;

        return 0;
}

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        return mkdir_safe_internal(path, mode, uid, gid, mkdir);
}

int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir) {
        const char *p, *e;
        int r;

        assert(path);

        if (prefix && !path_startswith(path, prefix))
                return -ENOTDIR;

        /* return immediately if directory exists */
        e = strrchr(path, '/');
        if (!e)
                return -EINVAL;

        if (e == path)
                return 0;

        p = strndupa(path, e - path);
        r = is_dir(p, true);
        if (r > 0)
                return 0;
        if (r == 0)
                return -ENOTDIR;

        /* create every parent directory in the path, except the last component */
        p = path + strspn(path, "/");
        for (;;) {
                char t[strlen(path) + 1];

                e = p + strcspn(p, "/");
                p = e + strspn(e, "/");

                /* Is this the last component? If so, then we're
                 * done */
                if (*p == 0)
                        return 0;

                memcpy(t, path, e - path);
                t[e-path] = 0;

                if (prefix && path_startswith(prefix, t))
                        continue;

                r = _mkdir(t, mode);
                if (r < 0 && errno != EEXIST)
                        return -errno;
        }
}

int mkdir_parents(const char *path, mode_t mode) {
        return mkdir_parents_internal(NULL, path, mode, mkdir);
}

int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir) {
        int r;

        /* Like mkdir -p */

        r = mkdir_parents_internal(prefix, path, mode, _mkdir);
        if (r < 0)
                return r;

        r = _mkdir(path, mode);
        if (r < 0 && (errno != EEXIST || is_dir(path, true) <= 0))
                return -errno;

        return 0;
}

int mkdir_p(const char *path, mode_t mode) {
        return mkdir_p_internal(NULL, path, mode, mkdir);
}
