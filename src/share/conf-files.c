/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf-files.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int files_add(Hashmap *h, const char *root, const char *path, const char *suffix) {
        _cleanup_closedir_ DIR *dir = NULL;
        const char *dirpath;
        struct dirent *de;
        int r;

        assert(path);
        assert(suffix);

        dirpath = prefix_roota(root, path);

        dir = opendir(dirpath);
        if (!dir) {
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        FOREACH_DIRENT(de, dir, return -errno) {
                char *p;

                if (!dirent_is_file_with_suffix(de, suffix))
                        continue;

                p = strjoin(dirpath, "/", de->d_name, NULL);
                if (!p)
                        return -ENOMEM;

                r = hashmap_put(h, basename(p), p);
                if (r == -EEXIST) {
                        log_debug("Skipping overridden file: %s.", p);
                        free(p);
                } else if (r < 0) {
                        free(p);
                        return r;
                } else if (r == 0) {
                        log_debug("Duplicate file %s", p);
                        free(p);
                }
        }

        return 0;
}

static int base_cmp(const void *a, const void *b) {
        const char *s1, *s2;

        s1 = *(char * const *)a;
        s2 = *(char * const *)b;
        return strcmp(basename(s1), basename(s2));
}

static int conf_files_list_strv_internal(char ***strv, const char *suffix, const char *root, char **dirs) {
        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        char **files, **p;
        int r;

        assert(strv);
        assert(suffix);

        /* This alters the dirs string array */
        if (!path_strv_resolve_uniq(dirs, root))
                return -ENOMEM;

        fh = hashmap_new(&string_hash_ops);
        if (!fh)
                return -ENOMEM;

        STRV_FOREACH(p, dirs) {
                r = files_add(fh, root, *p, suffix);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to search for files in %s, ignoring: %m", *p);
        }

        files = hashmap_get_strv(fh);
        if (!files)
                return -ENOMEM;

        qsort_safe(files, hashmap_size(fh), sizeof(char *), base_cmp);
        *strv = files;

        return 0;
}

int conf_files_list_strv(char ***strv, const char *suffix, const char *root, const char* const* dirs) {
        _cleanup_strv_free_ char **copy = NULL;

        assert(strv);
        assert(suffix);

        copy = strv_copy((char**) dirs);
        if (!copy)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, copy);
}

int conf_files_list_nulstr(char ***strv, const char *suffix, const char *root, const char *d) {
        _cleanup_strv_free_ char **dirs = NULL;

        assert(strv);
        assert(suffix);

        dirs = strv_split_nulstr(d);
        if (!dirs)
                return -ENOMEM;

        return conf_files_list_strv_internal(strv, suffix, root, dirs);
}
