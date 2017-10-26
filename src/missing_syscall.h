#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2016 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/* Missing glibc definitions to access certain kernel APIs */

/* ======================================================================= */

#if !HAVE_GETRANDOM
#  ifndef __NR_getrandom
#    if defined __x86_64__
#      define __NR_getrandom 318
#    elif defined(__i386__)
#      define __NR_getrandom 355
#    elif defined(__arm__)
#      define __NR_getrandom 384
#   elif defined(__aarch64__)
#      define __NR_getrandom 278
#    elif defined(__ia64__)
#      define __NR_getrandom 1339
#    elif defined(__m68k__)
#      define __NR_getrandom 352
#    elif defined(__s390x__)
#      define __NR_getrandom 349
#    elif defined(__powerpc__)
#      define __NR_getrandom 359
#    elif defined _MIPS_SIM
#      if _MIPS_SIM == _MIPS_SIM_ABI32
#        define __NR_getrandom 4353
#      endif
#      if _MIPS_SIM == _MIPS_SIM_NABI32
#        define __NR_getrandom 6317
#      endif
#      if _MIPS_SIM == _MIPS_SIM_ABI64
#        define __NR_getrandom 5313
#      endif
#    else
#      warning "__NR_getrandom unknown for your architecture"
#    endif
#  endif

static inline int getrandom(void *buffer, size_t count, unsigned flags) {
#  ifdef __NR_getrandom
        return syscall(__NR_getrandom, buffer, count, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

/* ======================================================================= */

#if !HAVE_GETTID
static inline pid_t gettid(void) {
        return (pid_t) syscall(SYS_gettid);
}
#endif

