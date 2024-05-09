/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "string-util.h"

size_t iovec_total_size(const struct iovec *iovec, size_t n) {
        size_t sum = 0;

        assert(iovec || n == 0);

        FOREACH_ARRAY(j, iovec, n)
                sum += j->iov_len;

        return sum;
}

bool iovec_increment(struct iovec *iovec, size_t n, size_t k) {
        assert(iovec || n == 0);

        /* Returns true if there is nothing else to send (bytes written cover all of the iovec),
         * false if there's still work to do. */

        FOREACH_ARRAY(j, iovec, n) {
                size_t sub;

                if (j->iov_len == 0)
                        continue;
                if (k == 0)
                        return false;

                sub = MIN(j->iov_len, k);
                j->iov_len -= sub;
                j->iov_base = (uint8_t*) j->iov_base + sub;
                k -= sub;
        }

        assert(k == 0); /* Anything else would mean that we wrote more bytes than available,
                         * or the kernel reported writing more bytes than sent. */
        return true;
}

void iovec_array_free(struct iovec *iovec, size_t n_iovec) {
        assert(iovec || n_iovec == 0);

        FOREACH_ARRAY(i, iovec, n_iovec)
                free(i->iov_base);

        free(iovec);
}
