/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>
#include <stdbool.h>

#include "socket-util.h"
#include "openssl-util.h"

typedef enum OpenSSLCertificateAuthMode {
        OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE     = 0,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW    = 1,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY     = 2,
        OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN     = 3,
        _OPEN_SSL_CERTIFICATE_AUTH_MODE_MAX,
        _OPEN_SSL_CERTIFICATE_AUTH_MODE_INVALID = -EINVAL,
} OpenSSLCertificateAuthMode;

typedef enum SSLTransportType {
        SSL_TRANSPORT_TLS,
        SSL_TRANSPORT_DTLS,
} SSLTransportType;

typedef struct SSLManager SSLManager;

struct SSLManager {
        SSL_CTX *ctx;
        SSL *ssl;

        char *pretty_address;
        int fd;

        bool connected;
        OpenSSLCertificateAuthMode auth_mode;
        SSLTransportType transport_type;
};

void ssl_manager_free(SSLManager *m);
int ssl_manager_init(SSLTransportType type, OpenSSLCertificateAuthMode auth, const char *server_cert, SSLManager **ret);

int ssl_connect(SSLManager *m, SocketAddress *addr);
void ssl_disconnect(SSLManager *m);

int ssl_writev(SSLManager *m, const struct iovec *iov, size_t iovcnt);

const char *certificate_auth_mode_to_string(OpenSSLCertificateAuthMode v) _const_;
OpenSSLCertificateAuthMode certificate_auth_mode_from_string(const char *s) _pure_;

const char *ssl_transport_type_to_string(SSLTransportType type) _const_;

DEFINE_TRIVIAL_CLEANUP_FUNC(SSLManager*, ssl_manager_free);
