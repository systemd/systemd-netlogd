/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "netlog-tls.h"
#include "string-table.h"

static const char *const certificate_auth_mode_table[OPEN_SSL_CERTIFICATE_AUTH_MODE_MAX] = {
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE]  = "no",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW] = "allow",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY]  = "deny",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN]  = "warn",
};

DEFINE_STRING_TABLE_LOOKUP(certificate_auth_mode, int);

int ssl_verify_certificate_validity(int s, X509_STORE_CTX *store) {
        SSL* ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
        SocketAddress *address = (SocketAddress *) SSL_get_ex_data(ssl, 1);
        _cleanup_(OPENSSL_freep) void *subject = NULL, *issuer = NULL;
        TLSManager *m = (TLSManager *) SSL_get_ex_data(ssl, 0);
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int error = X509_STORE_CTX_get_error(store);
        int verify_mode = SSL_get_verify_mode(ssl);
        _cleanup_free_ char *pretty = NULL;
        union sockaddr_union sa;
        int r;

        assert(store);

        r = sockaddr_pretty(&address->sockaddr.sa, address->sockaddr.sa.sa_family == AF_INET ?
                            sizeof(sa.in) : sizeof(sa.in6), true, true, &pretty);
        if (r < 0)
                return r;

        log_debug("Verifying SSL ceritificates of server: %s", pretty);

        if (cert) {
                subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        }

        if (verify_mode == SSL_VERIFY_NONE) {
                 log_debug("SSL Certificate validation DISABLED but Error at depth: %d, issuer=%s, subject=%s: server=%s %s",
                           depth, (char *) subject, (char *) issuer, pretty, X509_verify_cert_error_string(error));

                 return 1;
        }

        r = SSL_get_verify_result(ssl);
        if (r != X509_V_OK) {
                switch(r) {
                        case X509_V_ERR_CERT_HAS_EXPIRED: {
                                switch (m->auth_mode) {
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY: {
                                                log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                "Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(r));
                                                return 0;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN: {
                                                log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                  "Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(r));

                                                return 1;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW: {
                                                log_debug("Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(r));
                                                return 1;
                                        }

                                                break;
                                        default:
                                                break;
                                }}
                                break;
                        case X509_V_ERR_CERT_REVOKED: {
                                switch (m->auth_mode) {
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY: {
                                                log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                "Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(r));
                                                return 0;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN: {
                                                log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                  "Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(r));

                                                return 1;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW: {
                                                log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                "Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(r));
                                                return 1;
                                        }
                                                break;
                                        default:
                                                break;
                                }}
                                break;
                        default:
                                log_error("Failed to validate remote certificate server=%s: %s. Aborting connection ...", pretty, X509_verify_cert_error_string(r));
                                return 0;
                }
        }

        log_debug("SSL ceritificates verified server=%s: %s", pretty, X509_verify_cert_error_string(r));

        return 1;
}

static int tls_write(TLSManager *m, const char *buf, size_t count) {
        int r;

        assert(m);
        assert(m->ssl);
        assert(buf);
        assert(count > 0);
        assert(count < INT_MAX);

        ERR_clear_error();
        r = SSL_write(m->ssl, buf, count);
        if (r <= 0)
                return log_error_errno(r, "Failed to invoke SSL_write: %s", TLS_ERROR_STRING(SSL_get_error(m->ssl, r)));

        return log_debug("Successful TLS SSL_write: %d bytes", r);
}

int tls_stream_writev(TLSManager *m, const struct iovec *iov, size_t iovcnt) {
        _cleanup_free_ char *buf = NULL;
        size_t count;

        assert(m);
        assert(iov);

        /* single buffer. Suboptimal, but better than multiple SSL_write calls. */
        count = iovec_total_size(iov, iovcnt);
        assert(count > 0);
        buf = new(char, count);
        if (!buf)
                return log_oom();

        for (size_t i = 0, pos = 0; i < iovcnt; pos += iov[i].iov_len, i++)
                memcpy(buf + pos, iov[i].iov_base, iov[i].iov_len);

        return tls_write(m, buf, count);
}

int tls_connect(TLSManager *m, SocketAddress *address) {
        _cleanup_(BIO_freep) BIO *bio = NULL;
        _cleanup_(SSL_freep) SSL *ssl = NULL;
        _cleanup_free_ char *pretty = NULL;
        const SSL_CIPHER *cipher;
        union sockaddr_union sa;
        socklen_t salen;
        SSL_CTX *ctx;
        int fd, r;

        assert(m);
        assert(address);

        switch (address->sockaddr.sa.sa_family) {
                case AF_INET:
                        sa = (union sockaddr_union) {
                        .in.sin_family = address->sockaddr.sa.sa_family,
                        .in.sin_port = address->sockaddr.in.sin_port,
                        .in.sin_addr = address->sockaddr.in.sin_addr,
                };
                        salen = sizeof(sa.in);
                        break;
                case AF_INET6:
                        sa = (union sockaddr_union) {
                        .in6.sin6_family = address->sockaddr.sa.sa_family,
                        .in6.sin6_port = address->sockaddr.in6.sin6_port,
                        .in6.sin6_addr = address->sockaddr.in6.sin6_addr,
                };
                        salen = sizeof(sa.in6);
                        break;
                default:
                        return -EAFNOSUPPORT;
        }

        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate socket: %m");;

        r = sockaddr_pretty(&address->sockaddr.sa, salen, true, true, &pretty);
        if (r < 0)
                return r;

        r = connect(fd, &address->sockaddr.sa, salen);
        if (r < 0 && errno != EINPROGRESS)
                return log_error_errno(errno, "Failed to connect to remote server='%s': %m", pretty);;

        log_debug("Connected to remote server: '%s'", pretty);

        ctx = SSL_CTX_new(SSLv23_client_method());
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "Failed to allocate memory for SSL CTX: %m");

        ssl = SSL_new(ctx);
        if (!ssl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "Failed to allocate memory for ssl: %s",
                                       ERR_error_string(ERR_get_error(), NULL));
        r = SSL_set_fd(ssl, fd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to SSL_set_fd: %s",
                                       ERR_error_string(ERR_get_error(), NULL));
        /* Cerification verification  */
        if (m->auth_mode != OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE && m->auth_mode != OPEN_SSL_CERTIFICATE_AUTH_MODE_INVALID) {
                log_debug("TLS: enable certificate verification");

                SSL_set_ex_data(ssl, 0, m);
                SSL_set_ex_data(ssl, 1, address);

                SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_certificate_validity);
        } else {
                log_debug("TLS: disable certificate verification");
                SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }

        SSL_CTX_set_default_verify_paths(ctx);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        r = SSL_connect(ssl);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "Failed to SSL_connect: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        cipher = SSL_get_current_cipher(ssl);

        log_debug("SSL: Cipher Version: %s Name: %s", SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher));
        if (DEBUG_LOGGING) {
                _cleanup_(X509_freep) X509* cert = NULL;

                cert = SSL_get_peer_certificate(ssl);
                if (cert) {
                        _cleanup_(OPENSSL_freep) void *subject = NULL, *issuer = NULL;

                        subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                        log_debug("SSL: Subject: %s", (char *) subject);

                        issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                        log_debug("SSL: Issuer: %s", (char *) issuer);
                } else
                        log_debug("SSL: No certificates.");

        }

        m->bio = TAKE_PTR(bio);
        m->ssl = TAKE_PTR(ssl);
        m->ctx = ctx;
        m->fd = fd;

        m->connected = true;
        return 0;
}

void tls_disconnect(TLSManager *m) {
        if (!m)
                return;

        ERR_clear_error();

        if (m->ssl) {
                SSL_shutdown(m->ssl);
                SSL_free(m->ssl);
                m->ssl = NULL;
        }

        m->fd = safe_close(m->fd);
        m->connected = false;;
}

void tls_manager_free(TLSManager *m) {
        if (!m)
                return;

        if (m->ctx)
                SSL_CTX_free(m->ctx);

        free(m);
}

int tls_manager_init(OpenSSLCertificateAuthMode auth, TLSManager **ret ) {
        _cleanup_(tls_manager_freep) TLSManager *m = NULL;

        m = new(TLSManager, 1);
        if (!m)
                return log_oom();

        *m = (TLSManager) {
           .auth_mode = auth,
        };

        *ret = TAKE_PTR(m);
        return 0;
}
