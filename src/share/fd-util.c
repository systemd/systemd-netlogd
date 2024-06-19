/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "util.h"

int close_nointr(int fd) {
        assert(fd >= 0);

        if (close(fd) >= 0)
                return 0;

        /*
         * Just ignore EINTR; a retry loop is the wrong thing to do on
         * Linux.
         *
         * http://lkml.indiana.edu/hypermail/linux/kernel/0509.1/0877.html
         * https://bugzilla.gnome.org/show_bug.cgi?id=682819
         * http://utcc.utoronto.ca/~cks/space/blog/unix/CloseEINTR
         * https://sites.google.com/site/michaelsafyan/software-engineering/checkforeintrwheninvokingclosethinkagain
         */
        if (errno == EINTR)
                return 0;

        return -errno;
}

int safe_close(int fd) {

        /*
         * Like close_nointr() but cannot fail. Guarantees errno is
         * unchanged. Is a NOP with negative fds passed, and returns
         * -1, so that it can be used in this syntax:
         *
         * fd = safe_close(fd);
         */

        if (fd >= 0) {
                PROTECT_ERRNO;

                /* The kernel might return pretty much any error code
                 * via close(), but the fd will be closed anyway. The
                 * only condition we want to check for here is whether
                 * the fd was invalid at all... */

                assert_se(close_nointr(fd) != -EBADF);
        }

        return -1;
}

void close_many(const int fds[], unsigned n_fd) {
        unsigned i;

        assert(fds || n_fd <= 0);

        for (i = 0; i < n_fd; i++)
                safe_close(fds[i]);
}

int fclose_nointr(FILE *f) {
        assert(f);

        /* Same as close_nointr(), but for fclose() */

        if (fclose(f) == 0)
                return 0;

        if (errno == EINTR)
                return 0;

        return -errno;
}

FILE* safe_fclose(FILE *f) {

        /* Same as safe_close(), but for fclose() */

        if (f) {
                PROTECT_ERRNO;

                assert_se(fclose_nointr(f) != EBADF);
        }

        return NULL;
}

int fd_cloexec(int fd, bool cloexec) {
        int flags, nflags;

        assert(fd >= 0);

        flags = fcntl(fd, F_GETFD, 0);
        if (flags < 0)
                return -errno;

        if (cloexec)
                nflags = flags | FD_CLOEXEC;
        else
                nflags = flags & ~FD_CLOEXEC;

        if (nflags == flags)
                return 0;

        if (fcntl(fd, F_SETFD, nflags) < 0)
                return -errno;

        return 0;
}

int fd_nonblock(int fd, bool nonblock) {
        int flags, nflags;

        assert(fd >= 0);

        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0)
                return -errno;

        nflags = UPDATE_FLAG(flags, O_NONBLOCK, nonblock);
        if (nflags == flags)
                return 0;

        return RET_NERRNO(fcntl(fd, F_SETFL, nflags));
}

void stdio_unset_cloexec(void) {
        fd_cloexec(STDIN_FILENO, false);
        fd_cloexec(STDOUT_FILENO, false);
        fd_cloexec(STDERR_FILENO, false);
}

void cmsg_close_all(struct msghdr *mh) {
        struct cmsghdr *cmsg;

        assert(mh);

        CMSG_FOREACH(cmsg, mh)
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
                        close_many((int*) CMSG_DATA(cmsg), (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
}

int fd_move_above_stdio(int fd) {
        int flags, copy;
        PROTECT_ERRNO;

        /* Moves the specified file descriptor if possible out of the range [0…2], i.e. the range of
         * stdin/stdout/stderr. If it can't be moved outside of this range the original file descriptor is
         * returned. This call is supposed to be used for long-lasting file descriptors we allocate in our code that
         * might get loaded into foreign code, and where we want ensure our fds are unlikely used accidentally as
         * stdin/stdout/stderr of unrelated code.
         *
         * Note that this doesn't fix any real bugs, it just makes it less likely that our code will be affected by
         * buggy code from others that mindlessly invokes 'fprintf(stderr, …' or similar in places where stderr has
         * been closed before.
         *
         * This function is written in a "best-effort" and "least-impact" style. This means whenever we encounter an
         * error we simply return the original file descriptor, and we do not touch errno. */

        if (fd < 0 || fd > 2)
                return fd;

        flags = fcntl(fd, F_GETFD, 0);
        if (flags < 0)
                return fd;

        if (flags & FD_CLOEXEC)
                copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        else
                copy = fcntl(fd, F_DUPFD, 3);
        if (copy < 0)
                return fd;

        assert(copy > 2);

        (void) close(fd);
        return copy;
}
