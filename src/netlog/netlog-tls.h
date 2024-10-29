/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>
#include <stdbool.h>

#include "socket-util.h"
#include "openssl-util.h"

typedef enum OpenSSLCertificateAuthMode {
        OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE     = 1 << 0,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW    = 1 << 1,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY     = 1 << 2,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN     = 1 << 3,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_MAX      = 1 << 4,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_INVALID  = -1,
} OpenSSLCertificateAuthMode;

typedef struct TLSManager TLSManager;

struct TLSManager {
        SSL_CTX *ctx;
        SSL *ssl;

        char *pretty_address;
        int fd;

        bool connected;
        OpenSSLCertificateAuthMode auth_mode;
};

void tls_manager_free(TLSManager *m);
int tls_manager_init(OpenSSLCertificateAuthMode auth, TLSManager **ret);

int tls_connect(TLSManager *m, SocketAddress *addr);
void tls_disconnect(TLSManager *m);

int tls_stream_writev(TLSManager *m, const struct iovec *iov, size_t iovcnt);

const char *certificate_auth_mode_to_string(int v) _const_;
int certificate_auth_mode_from_string(const char *s) _pure_;


DEFINE_TRIVIAL_CLEANUP_FUNC(TLSManager*, tls_manager_free);
