/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-tls.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"

#include "string-table.h"

#include "netlog-ssl.h"

static const char *const certificate_auth_mode_table[OPEN_SSL_CERTIFICATE_AUTH_MODE_MAX] = {
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE]  = "no",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW] = "allow",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY]  = "deny",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN]  = "warn",
};

DEFINE_STRING_TABLE_LOOKUP(certificate_auth_mode, int);

static int tls_write(TLSManager *m, const char *buf, size_t count) {
        int r;

        assert(m);
        assert(m->ssl);
        assert(buf);
        assert(count > 0);
        assert(count < INT_MAX);

        ERR_clear_error();
        r = SSL_write(m->ssl, buf, count);
        if (r <= 0) {
                int error = SSL_get_error(m->ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE))
                        return log_info_errno(SYNTHETIC_ERRNO(EAGAIN), "TLS: Failed to invoke SSL_write: %s", TLS_ERROR_STRING(error));
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EPIPE), "TLS: Failed to invoke SSL_write: %s", TLS_ERROR_STRING(error));
        }

        return log_debug("TLS: Successful TLS SSL_write: %d bytes", r);
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
        _cleanup_(SSL_freep) SSL *ssl = NULL;
        _cleanup_free_ char *pretty = NULL;
        const SSL_CIPHER *cipher;
        socklen_t salen;
        _cleanup_close_ int fd = -1;
        int r;

        assert(m);
        assert(m->ctx);
        assert(address);

        switch (address->sockaddr.sa.sa_family) {
                case AF_INET:
                        salen = sizeof(address->sockaddr.in);
                        break;
                case AF_INET6:
                        salen = sizeof(address->sockaddr.in6);
                        break;
                default:
                        return -EAFNOSUPPORT;
        }

        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0)
                return log_error_errno(errno, "TLS: Failed to allocate socket: %m");

        r = sockaddr_pretty(&address->sockaddr.sa, salen, true, true, &pretty);
        if (r < 0)
                return r;

        r = connect(fd, &address->sockaddr.sa, salen);
        if (r < 0 && errno != EINPROGRESS)
                return log_error_errno(errno, "TLS: Failed to connect to remote server='%s': %m", pretty);

        log_debug("TLS: Connected to remote server: '%s'", pretty);

        ssl = SSL_new(m->ctx);
        if (!ssl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "TLS: Failed to allocate memory for ssl: %s",
                                       ERR_error_string(ERR_get_error(), NULL));
        r = SSL_set_fd(ssl, fd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "TLS: Failed to SSL_set_fd: %s",
                                       ERR_error_string(ERR_get_error(), NULL));
        /* Certification verification  */
        if (m->auth_mode != OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE && m->auth_mode != OPEN_SSL_CERTIFICATE_AUTH_MODE_INVALID) {
                log_debug("TLS: enable certificate verification");

                SSL_set_ex_data(ssl, 0, m);
                SSL_set_ex_data(ssl, 1, address);

                SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_certificate_validity);
        } else {
                log_debug("TLS: disable certificate verification");
                SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        }

        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        r = SSL_connect(ssl);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "TLS: Failed to SSL_connect: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        cipher = SSL_get_current_cipher(ssl);

        log_debug("TLS: SSL Cipher Version: %s Name: %s", SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher));
        if (DEBUG_LOGGING) {
                _cleanup_(X509_freep) X509* cert = NULL;

                cert = SSL_get_peer_certificate(ssl);
                if (cert) {
                        _cleanup_(OPENSSL_freep) void *subject = NULL, *issuer = NULL;

                        subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                        log_debug("TLS: SSL Subject: %s", (char *) subject);

                        issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                        log_debug("TLS: SSL Issuer: %s", (char *) issuer);
                } else
                        log_debug("TLS: SSL No certificates.");

        }

        m->ssl = TAKE_PTR(ssl);
        m->fd = TAKE_FD(fd);

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
        m->connected = false;
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
        _cleanup_(SSL_CTX_freep) SSL_CTX *ctx = NULL;

        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "TLS: Failed to allocate memory for SSL CTX: %m");

        SSL_CTX_set_default_verify_paths(ctx);

        m = new(TLSManager, 1);
        if (!m)
                return log_oom();

        *m = (TLSManager) {
           .auth_mode = auth,
           .ctx = TAKE_PTR(ctx),
           .fd = -1,
        };

        *ret = TAKE_PTR(m);
        return 0;
}
