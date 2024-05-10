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
#include "netlog-dtls.h"

static ssize_t dtls_write(DTLSManager *m, const char *buf, size_t count) {
        int r;

        assert(m);
        assert(buf);

        ERR_clear_error();
        r = SSL_write(m->ssl, buf, count);
        if (r <= 0)
                return log_error_errno(r, "Failed to invoke SSL_write: %s", TLS_ERROR_STRING(SSL_get_error(m->ssl, r)));

        if (r > 0)
                return log_debug("Successful DTLS SSL_write: %d bytes", r);

        return 0;
}

ssize_t dtls_datagram_writev(DTLSManager *m, const struct iovec *iov, size_t iovcnt) {
        _cleanup_free_ char *buf = NULL;
        size_t count;

        assert(m);
        assert(m->ssl);
        assert(iov);
        assert(iovec_total_size(iov, iovcnt) > 0);

        /* single buffer. Suboptimal, but better than multiple SSL_write calls. */
        count = iovec_total_size(iov, iovcnt);
        buf = new(char, count);
        for (size_t i = 0, pos = 0; i < iovcnt; pos += iov[i].iov_len, i++)
                memcpy(buf + pos, iov[i].iov_base, iov[i].iov_len);

        return dtls_write(m, buf, count);
}

int dtls_connect(DTLSManager *m, SocketAddress *address) {
        _cleanup_(BIO_freep) BIO *bio = NULL;
        _cleanup_(SSL_freep) SSL *ssl = NULL;
        _cleanup_free_ char *pretty = NULL;
        const SSL_CIPHER *cipher;
        union sockaddr_union sa;
        socklen_t salen;
        SSL_CTX *ctx;
        struct timeval timeout = {
                .tv_sec = 3,
                .tv_usec = 0,
        };
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

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate socket: %m");;

        r = sockaddr_pretty(&address->sockaddr.sa, salen, true, true, &pretty);
        if (r < 0)
                return r;

        r = connect(fd, &address->sockaddr.sa, salen);
        if (r < 0 && errno != EINPROGRESS)
                return log_error_errno(errno, "Failed to connect to remote server='%s': %m", pretty);;

        log_debug("Connected to remote server: '%s'", pretty);

        ctx = SSL_CTX_new(DTLS_method());
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "Failed to allocate memory for SSL CTX: %m");

        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_default_verify_paths(ctx);

        ssl = SSL_new(ctx);
        if (!ssl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "Failed to allocate memory for ssl: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        /* Create BIO from socket array! */
        bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        if (!bio)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "Failed to allocate memory for bio: %m");

        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &address);
        SSL_set_bio(ssl , bio, bio);

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
                        log_debug("DTLS: Subject: %s", (char *) subject);

                        issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                        log_debug("DTLS: Issuer: %s", (char *) issuer);
                } else
                        log_debug("DTLS: No certificates.");
        }

        /* Set reference in SSL obj */
        SSL_set_ex_data(ssl, 0, NULL);
        SSL_set_ex_data(ssl, 1, NULL);

        /* Set and activate timeouts */
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        m->bio = TAKE_PTR(bio);
        m->ssl = TAKE_PTR(ssl);
        m->ctx = ctx;
        m->fd = fd;

        m->connected = true;
        return 0;
}

void dtls_disconnect(DTLSManager *m) {
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

void dtls_manager_free(DTLSManager *m) {
        if (!m)
                return;

        if (m->ctx)
                SSL_CTX_free(m->ctx);

        free(m);
}

int dtls_manager_init(DTLSManager **ret) {
        _cleanup_(dtls_manager_freep) DTLSManager *m = NULL;

        m = new0(DTLSManager, 1);
        if (!m)
                return log_oom();

        *ret = TAKE_PTR(m);
        return 0;
}
