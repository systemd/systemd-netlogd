/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netlog-ssl-common.h"

/* TLSManager is now an alias for SSLManager for backwards compatibility */
typedef SSLManager TLSManager;

static inline void tls_manager_free(TLSManager *m) {
        ssl_manager_free(m);
}

static inline int tls_manager_init(OpenSSLCertificateAuthMode auth, const char *server_cert, TLSManager **ret) {
        return ssl_manager_init(SSL_TRANSPORT_TLS, auth, server_cert, ret);
}

static inline int tls_connect(TLSManager *m, SocketAddress *addr) {
        return ssl_connect(m, addr);
}

static inline void tls_disconnect(TLSManager *m) {
        ssl_disconnect(m);
}

static inline int tls_stream_writev(TLSManager *m, const struct iovec *iov, size_t iovcnt) {
        return ssl_writev(m, iov, iovcnt);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(TLSManager*, tls_manager_free);
