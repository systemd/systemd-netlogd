/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/if_link.h>
#include <linux/input.h>
#include <linux/loop.h>
#include <linux/neighbour.h>
#include <linux/oom.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <uchar.h>
#include <unistd.h>

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "macro.h"

#if defined(__i386__) || defined(__x86_64__)

/* The precise definition of __O_TMPFILE is arch specific, so let's
 * just define this on x86 where we know the value. */

#ifndef __O_TMPFILE
#define __O_TMPFILE     020000000
#endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#endif

#ifndef HAVE_KEY_SERIAL_T
typedef int32_t key_serial_t;
#endif

#include "missing_syscall.h"
