/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdbool.h>

#include "socket-util.h"

typedef struct DTLSManager DTLSManager;

struct DTLSManager {
        SSL_SESSION *session;
        SSL_CTX *ctx;
        BIO *bio;
        SSL *ssl;

        uint32_t events;
        int fd;

        bool shutdown;
        bool connected;

        BUF_MEM *write_buffer;
        size_t buffer_offset;
};

void dtls_manager_free(DTLSManager *m);
int dtls_manager_init(DTLSManager **m);

int dtls_connect(DTLSManager *m, SocketAddress *addr);
void dtls_disconnect(DTLSManager *m);

ssize_t dtls_stream_writev(DTLSManager *m, const struct iovec *iov, size_t iovcnt);

DEFINE_TRIVIAL_CLEANUP_FUNC(DTLSManager*, dtls_manager_free);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SSL*, SSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIO*, BIO_free, NULL);
