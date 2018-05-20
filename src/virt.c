/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering
***/

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "virt.h"

int detect_container(void) {

        static const struct {
                const char *value;
                int id;
        } value_table[] = {
                { "lxc",            VIRTUALIZATION_LXC            },
                { "lxc-libvirt",    VIRTUALIZATION_LXC_LIBVIRT    },
                { "systemd-nspawn", VIRTUALIZATION_SYSTEMD_NSPAWN },
                { "docker",         VIRTUALIZATION_DOCKER         },
                { "rkt",            VIRTUALIZATION_RKT            },
        };

        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        _cleanup_free_ char *m = NULL;
        const char *e = NULL;
        unsigned j;
        int r;

        if (cached_found >= 0)
                return cached_found;

        /* /proc/vz exists in container and outside of the container,
         * /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) >= 0 &&
            access("/proc/bc", F_OK) < 0) {
                r = VIRTUALIZATION_OPENVZ;
                goto finish;
        }

        if (getpid() == 1) {
                /* If we are PID 1 we can just check our own
                 * environment variable */

                e = getenv("container");
                if (isempty(e)) {
                        r = VIRTUALIZATION_NONE;
                        goto finish;
                }
        } else {

                /* Otherwise, PID 1 dropped this information into a
                 * file in /run. This is better than accessing
                 * /proc/1/environ, since we don't need CAP_SYS_PTRACE
                 * for that. */

                r = read_one_line_file("/run/systemd/container", &m);
                if (r == -ENOENT) {

                        /* Fallback for cases where PID 1 was not
                         * systemd (for example, cases where
                         * init=/bin/sh is used. */

                        r = getenv_for_pid(1, "container", &m);
                        if (r <= 0) {

                                /* If that didn't work, give up,
                                 * assume no container manager.
                                 *
                                 * Note: This means we still cannot
                                 * detect containers if init=/bin/sh
                                 * is passed but privileges dropped,
                                 * as /proc/1/environ is only readable
                                 * with privileges. */

                                r = VIRTUALIZATION_NONE;
                                goto finish;
                        }
                }
                if (r < 0)
                        return r;

                e = m;
        }

        for (j = 0; j < ELEMENTSOF(value_table); j++)
                if (streq(e, value_table[j].value)) {
                        r = value_table[j].id;
                        goto finish;
                }

        r = VIRTUALIZATION_CONTAINER_OTHER;

finish:
        log_debug("Found container virtualization %s", virtualization_to_string(r));
        cached_found = r;
        return r;
}

int running_in_chroot(void) {
        int ret;

        ret = files_same("/proc/1/root", "/");
        if (ret < 0)
                return ret;

        return ret == 0;
}

static const char *const virtualization_table[_VIRTUALIZATION_MAX] = {
        [VIRTUALIZATION_NONE] = "none",
        [VIRTUALIZATION_KVM] = "kvm",
        [VIRTUALIZATION_QEMU] = "qemu",
        [VIRTUALIZATION_BOCHS] = "bochs",
        [VIRTUALIZATION_XEN] = "xen",
        [VIRTUALIZATION_UML] = "uml",
        [VIRTUALIZATION_VMWARE] = "vmware",
        [VIRTUALIZATION_ORACLE] = "oracle",
        [VIRTUALIZATION_MICROSOFT] = "microsoft",
        [VIRTUALIZATION_ZVM] = "zvm",
        [VIRTUALIZATION_PARALLELS] = "parallels",
        [VIRTUALIZATION_VM_OTHER] = "vm-other",

        [VIRTUALIZATION_SYSTEMD_NSPAWN] = "systemd-nspawn",
        [VIRTUALIZATION_LXC_LIBVIRT] = "lxc-libvirt",
        [VIRTUALIZATION_LXC] = "lxc",
        [VIRTUALIZATION_OPENVZ] = "openvz",
        [VIRTUALIZATION_DOCKER] = "docker",
        [VIRTUALIZATION_RKT] = "rkt",
        [VIRTUALIZATION_CONTAINER_OTHER] = "container-other",
};

DEFINE_STRING_TABLE_LOOKUP(virtualization, int);
