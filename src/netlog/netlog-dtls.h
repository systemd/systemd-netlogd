/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netlog-ssl-common.h"

/* DTLSManager is now an alias for SSLManager for backwards compatibility */
typedef SSLManager DTLSManager;

static inline void dtls_manager_free(DTLSManager *m) {
        ssl_manager_free(m);
}

static inline int dtls_manager_init(OpenSSLCertificateAuthMode auth_mode, const char *server_cert, DTLSManager **ret) {
        return ssl_manager_init(SSL_TRANSPORT_DTLS, auth_mode, server_cert, ret);
}

static inline int dtls_connect(DTLSManager *m, SocketAddress *addr) {
        return ssl_connect(m, addr);
}

static inline void dtls_disconnect(DTLSManager *m) {
        ssl_disconnect(m);
}

static inline int dtls_datagram_writev(DTLSManager *m, const struct iovec *iov, size_t iovcnt) {
        return ssl_writev(m, iov, iovcnt);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DTLSManager*, dtls_manager_free);
