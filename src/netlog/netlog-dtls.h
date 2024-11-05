/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>
#include <stdbool.h>

#include "socket-util.h"
#include "openssl-util.h"
#include "netlog-tls.h"

typedef struct DTLSManager DTLSManager;

struct DTLSManager {
        SSL_CTX *ctx;
        SSL *ssl;

        char *pretty_address;
        int fd;
        bool connected;

        OpenSSLCertificateAuthMode auth_mode;
};

void dtls_manager_free(DTLSManager *m);
int dtls_manager_init(OpenSSLCertificateAuthMode auth_mode, DTLSManager **ret);

int dtls_connect(DTLSManager *m, SocketAddress *addr);
void dtls_disconnect(DTLSManager *m);

int dtls_datagram_writev(DTLSManager *m, const struct iovec *iov, size_t iovcnt);

DEFINE_TRIVIAL_CLEANUP_FUNC(DTLSManager*, dtls_manager_free);
