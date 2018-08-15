/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "hexdecoct.h"
#include "macro.h"
#include "util.h"

char octchar(int x) {
        return '0' + (x & 7);
}

int unoctchar(char c) {

        if (c >= '0' && c <= '7')
                return c - '0';

        return -EINVAL;
}

char decchar(int x) {
        return '0' + (x % 10);
}

int undecchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        return -EINVAL;
}

char hexchar(int x) {
        static const char table[16] = "0123456789abcdef";

        return table[x & 15];
}

int unhexchar(char c) {

        if (c >= '0' && c <= '9')
                return c - '0';

        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

        return -EINVAL;
}
