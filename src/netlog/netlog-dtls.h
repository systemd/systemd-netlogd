/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdbool.h>

#include "socket-util.h"
#include "openssl-util.h"

typedef struct DTLSManager DTLSManager;

struct DTLSManager {
        SSL_CTX *ctx;
        BIO *bio;
        SSL *ssl;

        int fd;
        bool connected;
};

void dtls_manager_free(DTLSManager *m);
int dtls_manager_init(DTLSManager **ret);

int dtls_connect(DTLSManager *m, SocketAddress *addr);
void dtls_disconnect(DTLSManager *m);

int dtls_datagram_writev(DTLSManager *m, const struct iovec *iov, size_t iovcnt);

DEFINE_TRIVIAL_CLEANUP_FUNC(DTLSManager*, dtls_manager_free);
