/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-ssl.h"

#include "alloc-util.h"
#include "openssl-util.h"
#include "socket-util.h"

#include "netlog-tls.h"

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
        long rc;

        assert(store);

        r = sockaddr_pretty(&address->sockaddr.sa, address->sockaddr.sa.sa_family == AF_INET ?
                            sizeof(sa.in) : sizeof(sa.in6), true, true, &pretty);
        if (r < 0)
                return r;

        log_debug("TLS: Verifying SSL certificates of server: %s", pretty);

        if (cert) {
                subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        }

        if (verify_mode == SSL_VERIFY_NONE) {
                 log_debug("TLS: SSL Certificate validation DISABLED but Error at depth: %d, issuer=%s, subject=%s: server=%s %s",
                           depth, (char *) subject, (char *) issuer, pretty, X509_verify_cert_error_string(error));

                 return 1;
        }

        rc = SSL_get_verify_result(ssl);
        if (rc != X509_V_OK) {
                switch(rc) {
                        case X509_V_ERR_CERT_HAS_EXPIRED: {
                                switch (m->auth_mode) {
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY: {
                                                log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                "TLS: Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(rc));
                                                return 0;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN: {
                                                log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                  "TLS: Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(rc));

                                                return 1;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW: {
                                                log_debug("TLS: Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(rc));
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
                                                                "TLS: Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(rc));
                                                return 0;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN: {
                                                log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                  "TLS: Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(rc));

                                                return 1;
                                        }
                                                break;
                                        case OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW: {
                                                log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                "TLS: Failed to verify certificate server=%s: %s", pretty, X509_verify_cert_error_string(rc));
                                                return 1;
                                        }
                                                break;
                                        default:
                                                break;
                                }}
                                break;
                        default:
                                log_error("TLS: Failed to validate remote certificate server=%s: %s. Aborting connection ...", pretty, X509_verify_cert_error_string(rc));
                                return 0;
                }
        }

        log_debug("TLS: SSL certificates verified server=%s: %s", pretty, X509_verify_cert_error_string(rc));

        return 1;
}
