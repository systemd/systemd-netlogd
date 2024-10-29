/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-dtls.h"

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

#include "netlog-ssl.h"

static int dtls_write(DTLSManager *m, const char *buf, size_t count) {
        int r;

        assert(m);
        assert(m->ssl);
        assert(m->pretty_address);
        assert(buf);
        assert(count > 0);
        assert(count < INT_MAX);

        ERR_clear_error();
        r = SSL_write(m->ssl, buf, count);
        if (r <= 0) {
                int error = SSL_get_error(m->ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE))
                        return log_info_errno(SYNTHETIC_ERRNO(EAGAIN), "DTLS: Failed to invoke SSL_write to %s: %s", m->pretty_address, TLS_ERROR_STRING(error));
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EPIPE), "DTLS: Failed to invoke SSL_write to %s: %s", m->pretty_address, TLS_ERROR_STRING(error));
        }

        return log_debug("DTLS: Successful SSL_write: %d bytes", r);
}

int dtls_datagram_writev(DTLSManager *m, const struct iovec *iov, size_t iovcnt) {
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

        return dtls_write(m, buf, count);
}

int dtls_connect(DTLSManager *m, SocketAddress *address) {
        _cleanup_(BIO_freep) BIO *bio = NULL;
        _cleanup_(SSL_freep) SSL *ssl = NULL;
        _cleanup_free_ char *pretty = NULL;
        const SSL_CIPHER *cipher;
        socklen_t salen;
        struct timeval timeout = {
                .tv_sec = 3,
                .tv_usec = 0,
        };
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

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
                return log_error_errno(errno, "DTLS: Failed to allocate socket: %m");

        r = sockaddr_pretty(&address->sockaddr.sa, salen, true, true, &pretty);
        if (r < 0)
                return r;

        r = connect(fd, &address->sockaddr.sa, salen);
        if (r < 0 && errno != EINPROGRESS)
                return log_error_errno(errno, "DTLS: Failed to connect to remote server='%s': %m", pretty);

        log_debug("DTLS: Connected to remote server: '%s'", pretty);

        ssl = SSL_new(m->ctx);
        if (!ssl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "DTLS: Failed to allocate memory for ssl: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        /* Create BIO from socket array! */
        bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        if (!bio)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "DTLS: Failed to allocate memory for bio: %m");

        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &address);
        SSL_set_bio(ssl, bio, bio);
        bio = NULL;

        /* Certification verification  */
        if (m->auth_mode != OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE) {
                log_debug("DTLS: enable certificate verification");

                SSL_set_ex_data(ssl, EX_DATA_TLSMANAGER, m);
                SSL_set_ex_data(ssl, EX_DATA_PRETTYADDRESS, pretty);
                SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_certificate_validity);
        } else {
                log_debug("DTLS: disable certificate verification");
                SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        }

        r = SSL_connect(ssl);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "DTLS: Failed to SSL_connect: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        cipher = SSL_get_current_cipher(ssl);

        log_debug("DTLS: SSL Cipher Version: %s Name: %s", SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher));
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

        /* Set and activate timeouts */
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        m->ssl = TAKE_PTR(ssl);
        m->fd = TAKE_FD(fd);
        m->pretty_address = TAKE_PTR(pretty);

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

        m->pretty_address = mfree(m->pretty_address);
        m->fd = safe_close(m->fd);
        m->connected = false;
}

void dtls_manager_free(DTLSManager *m) {
        if (!m)
                return;

        if (m->ctx)
                SSL_CTX_free(m->ctx);

        free(m);
}

int dtls_manager_init(OpenSSLCertificateAuthMode auth_mode, DTLSManager **ret) {
        _cleanup_(dtls_manager_freep) DTLSManager *m = NULL;
        _cleanup_(SSL_CTX_freep) SSL_CTX *ctx = NULL;

        ctx = SSL_CTX_new(DTLS_method());
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "DTLS: Failed to allocate memory for SSL CTX: %m");

        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify_depth(ctx, VERIFICATION_DEPTH + 1);

        m = new(DTLSManager, 1);
        if (!m)
                return log_oom();

        *m = (DTLSManager) {
           .auth_mode = auth_mode,
           .ctx = TAKE_PTR(ctx),
           .fd = -1,
        };

        *ret = TAKE_PTR(m);
        return 0;
}
