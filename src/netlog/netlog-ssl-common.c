/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-ssl-common.h"

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
#include "string-table.h"

#include "netlog-ssl.h"

static const char *const certificate_auth_mode_table[_OPEN_SSL_CERTIFICATE_AUTH_MODE_MAX] = {
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE]  = "no",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW] = "allow",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY]  = "deny",
        [OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN]  = "warn",
};

DEFINE_STRING_TABLE_LOOKUP(certificate_auth_mode, OpenSSLCertificateAuthMode);

static const char *const ssl_transport_type_table[] = {
        [SSL_TRANSPORT_TLS]  = "TLS",
        [SSL_TRANSPORT_DTLS] = "DTLS",
};

const char *ssl_transport_type_to_string(SSLTransportType type) {
        if (type < 0 || type >= (SSLTransportType) ELEMENTSOF(ssl_transport_type_table))
                return NULL;
        return ssl_transport_type_table[type];
}

static int ssl_write(SSLManager *m, const char *buf, size_t count) {
        const char *proto;
        int r;

        assert(m);
        assert(m->ssl);
        assert(m->pretty_address);
        assert(buf);
        assert(count > 0);
        assert(count < INT_MAX);

        proto = ssl_transport_type_to_string(m->transport_type);

        ERR_clear_error();
        r = SSL_write(m->ssl, buf, count);
        if (r <= 0) {
                int error = SSL_get_error(m->ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE))
                        return log_info_errno(SYNTHETIC_ERRNO(EAGAIN), "%s: Failed to invoke SSL_write to %s: %s", proto, m->pretty_address, TLS_ERROR_STRING(error));
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EPIPE), "%s: Failed to invoke SSL_write to %s: %s", proto, m->pretty_address, TLS_ERROR_STRING(error));
        }

        return log_debug("%s: Successful SSL_write: %d bytes", proto, r);
}

int ssl_writev(SSLManager *m, const struct iovec *iov, size_t iovcnt) {
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

        return ssl_write(m, buf, count);
}

static int ssl_setup_certificate_verification(SSLManager *m, SSL *ssl, const char *pretty) {
        const char *proto;

        assert(m);
        assert(ssl);
        assert(pretty);

        proto = ssl_transport_type_to_string(m->transport_type);

        if (m->auth_mode != OPEN_SSL_CERTIFICATE_AUTH_MODE_NONE) {
                log_debug("%s: enable certificate verification with mode %s", proto, certificate_auth_mode_to_string(m->auth_mode));

                SSL_set_ex_data(ssl, EX_DATA_TLSMANAGER, m);
                SSL_set_ex_data(ssl, EX_DATA_PRETTYADDRESS, (void *) pretty);

                SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_certificate_validity);
        } else {
                log_debug("%s: disable certificate verification", proto);
                SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        }

        return 0;
}

static int ssl_log_connection_info(SSLManager *m, SSL *ssl) {
        const SSL_CIPHER *cipher;
        const char *proto;

        assert(m);
        assert(ssl);

        proto = ssl_transport_type_to_string(m->transport_type);

        cipher = SSL_get_current_cipher(ssl);
        log_debug("%s: SSL Cipher Version: %s Name: %s", proto, SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher));

        if (DEBUG_LOGGING) {
                _cleanup_(X509_freep) X509* cert = NULL;

                cert = SSL_get_peer_certificate(ssl);
                if (cert) {
                        _cleanup_(OPENSSL_freep) void *subject = NULL, *issuer = NULL;

                        subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
                        log_debug("%s: SSL Subject: %s", proto, (char *) subject);

                        issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
                        log_debug("%s: SSL Issuer: %s", proto, (char *) issuer);
                } else
                        log_debug("%s: SSL No certificates.", proto);
        }

        return 0;
}

static int ssl_connect_tls(SSLManager *m, SocketAddress *address, const char *pretty, int fd) {
        _cleanup_(SSL_freep) SSL *ssl = NULL;
        const char *proto;
        int r;

        assert(m);
        assert(m->ctx);
        assert(address);
        assert(pretty);
        assert(fd >= 0);

        proto = ssl_transport_type_to_string(m->transport_type);

        ssl = SSL_new(m->ctx);
        if (!ssl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "%s: Failed to allocate memory for ssl: %s",
                                       proto, ERR_error_string(ERR_get_error(), NULL));

        r = SSL_set_fd(ssl, fd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "%s: Failed to SSL_set_fd: %s",
                                       proto, ERR_error_string(ERR_get_error(), NULL));

        ssl_setup_certificate_verification(m, ssl, pretty);

        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        r = SSL_connect(ssl);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "%s: Failed to SSL_connect: %s",
                                       proto, ERR_error_string(ERR_get_error(), NULL));

        ssl_log_connection_info(m, ssl);

        m->ssl = TAKE_PTR(ssl);
        return 0;
}

static int ssl_connect_dtls(SSLManager *m, SocketAddress *address, const char *pretty, int fd) {
        _cleanup_(BIO_freep) BIO *bio = NULL;
        _cleanup_(SSL_freep) SSL *ssl = NULL;
        const char *proto;
        struct timeval timeout = {
                .tv_sec = 3,
                .tv_usec = 0,
        };
        int r;

        assert(m);
        assert(m->ctx);
        assert(address);
        assert(pretty);
        assert(fd >= 0);

        proto = ssl_transport_type_to_string(m->transport_type);

        /* Create BIO from socket */
        bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        if (!bio)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "%s: Failed to allocate memory for bio: %m", proto);

        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &address->sockaddr.sa);
        /* Set and activate timeouts */
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        ssl = SSL_new(m->ctx);
        if (!ssl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "%s: Failed to allocate memory for ssl: %s",
                                       proto, ERR_error_string(ERR_get_error(), NULL));

        SSL_set_bio(ssl, bio, bio);
        TAKE_PTR(bio); /* SSL takes ownership */

        ssl_setup_certificate_verification(m, ssl, pretty);

        r = SSL_connect(ssl);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "%s: Failed to SSL_connect: %s",
                                       proto, ERR_error_string(ERR_get_error(), NULL));

        ssl_log_connection_info(m, ssl);

        m->ssl = TAKE_PTR(ssl);
        return 0;
}

int ssl_connect(SSLManager *m, SocketAddress *address) {
        _cleanup_free_ char *pretty = NULL;
        _cleanup_close_ int fd = -1;
        const char *proto;
        socklen_t salen;
        int sock_type, r;

        assert(m);
        assert(m->ctx);
        assert(address);

        proto = ssl_transport_type_to_string(m->transport_type);

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

        sock_type = m->transport_type == SSL_TRANSPORT_TLS ? SOCK_STREAM : SOCK_DGRAM;

        fd = socket(AF_INET, sock_type, m->transport_type == SSL_TRANSPORT_TLS ? IPPROTO_TCP : 0);
        if (fd < 0)
                return log_error_errno(errno, "%s: Failed to allocate socket: %m", proto);

        r = sockaddr_pretty(&address->sockaddr.sa, salen, true, true, &pretty);
        if (r < 0)
                return r;

        r = connect(fd, &address->sockaddr.sa, salen);
        if (r < 0 && errno != EINPROGRESS)
                return log_error_errno(errno, "%s: Failed to connect to remote server='%s': %m", proto, pretty);

        log_debug("%s: Connected to remote server: '%s'", proto, pretty);

        if (m->transport_type == SSL_TRANSPORT_TLS)
                r = ssl_connect_tls(m, address, pretty, fd);
        else
                r = ssl_connect_dtls(m, address, pretty, fd);

        if (r < 0)
                return r;

        m->fd = TAKE_FD(fd);
        m->pretty_address = TAKE_PTR(pretty);
        m->connected = true;

        return 0;
}

void ssl_disconnect(SSLManager *m) {
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

void ssl_manager_free(SSLManager *m) {
        if (!m)
                return;

        if (m->ctx)
                SSL_CTX_free(m->ctx);

        free(m);
}

int ssl_manager_init(SSLTransportType type, OpenSSLCertificateAuthMode auth, const char *server_cert, SSLManager **ret) {
        _cleanup_(ssl_manager_freep) SSLManager *m = NULL;
        _cleanup_(SSL_CTX_freep) SSL_CTX *ctx = NULL;
        const SSL_METHOD *method;
        const char *proto;
        int r;

        proto = ssl_transport_type_to_string(type);

        method = type == SSL_TRANSPORT_TLS ? TLS_client_method() : DTLS_method();

        ctx = SSL_CTX_new(method);
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "%s: Failed to allocate memory for SSL CTX: %m", proto);

        if (server_cert) {
                r = SSL_CTX_load_verify_file(ctx, server_cert);
                if (r != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "%s: Failed to load CA certificate from '%s': %s",
                                               proto, server_cert, ERR_error_string(ERR_get_error(), NULL));
        } else {
                r = SSL_CTX_set_default_verify_paths(ctx);
                if (r != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "%s: Failed to load default CA certificates: %s",
                                               proto, ERR_error_string(ERR_get_error(), NULL));
        }

        SSL_CTX_set_verify_depth(ctx, VERIFICATION_DEPTH + 1);

        m = new(SSLManager, 1);
        if (!m)
                return log_oom();

        *m = (SSLManager) {
           .auth_mode = auth,
           .ctx = TAKE_PTR(ctx),
           .fd = -1,
           .transport_type = type,
        };

        *ret = TAKE_PTR(m);
        return 0;
}
