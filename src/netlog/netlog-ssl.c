/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-ssl.h"

#include "alloc-util.h"
#include "openssl-util.h"
#include "socket-util.h"

#include "netlog-ssl-common.h"

static void extract_certificate_names(const X509 *cert, char *subject_buf, size_t subject_size, char *issuer_buf, size_t issuer_size) {
        X509_NAME_oneline(X509_get_subject_name(cert), subject_buf, subject_size);
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer_buf, issuer_size);
}

static int check_certificate_chain_depth(X509_STORE_CTX *store, int depth, int preverify_ok) {
        if (depth <= VERIFICATION_DEPTH)
                return preverify_ok;

        /*
         * From man:SSL_set_verify(3):
         *
         *   Catch a too long certificate chain. The depth limit set using
         *   SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
         *   that whenever the "depth>verify_depth" condition is met, we
         *   have violated the limit and want to log this error condition.
         *   We must do it here, because the CHAIN_TOO_LONG error would not
         *   be found explicitly; only errors introduced by cutting off the
         *   additional certificates would be logged.
         */
        X509_STORE_CTX_set_error(store, X509_V_ERR_CERT_CHAIN_TOO_LONG);
        return 0;
}

static int determine_verification_log_level(const SSLManager *m, int *preverify_ok) {
        int log_level;

        switch (m->auth_mode) {
                case OPEN_SSL_CERTIFICATE_AUTH_MODE_DENY:
                        log_level = LOG_ERR;
                        break;
                case OPEN_SSL_CERTIFICATE_AUTH_MODE_WARN:
                        log_level = LOG_WARNING;
                        *preverify_ok = 1;
                        break;
                case OPEN_SSL_CERTIFICATE_AUTH_MODE_ALLOW:
                        log_level = LOG_DEBUG;
                        *preverify_ok = 1;
                        break;
                default:
                        assert_not_reached("Invalid certificate authentication mode");
        }

        return log_level;
}

/* inspired by SSL_set_verify(3) */
int ssl_verify_certificate_validity(int preverify_ok, X509_STORE_CTX *store) {
        const SSL* ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
        const char *pretty = (const char *) SSL_get_ex_data(ssl, EX_DATA_PRETTYADDRESS);
        const SSLManager *m = (const SSLManager *) SSL_get_ex_data(ssl, EX_DATA_TLSMANAGER);
        const X509 *error_cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int error = X509_STORE_CTX_get_error(store);
        char subject_buf[256], issuer_buf[256];
        int log_level;

        assert(store);
        assert(pretty);
        assert(m);

        extract_certificate_names(error_cert, subject_buf, sizeof(subject_buf), issuer_buf, sizeof(issuer_buf));

        log_debug("TLS: Verifying SSL certificates of server %s: certificate: subject='%s' issuer='%s' depth=%d preverify_ok=%d error=%d/%s ...",
                  pretty, subject_buf, issuer_buf, depth, preverify_ok, error, X509_verify_cert_error_string(error));

        preverify_ok = check_certificate_chain_depth(store, depth, preverify_ok);

        if (preverify_ok) {
                log_debug("TLS: Verified SSL certificate of server=%s (certificate: subject='%s' issuer='%s' depth=%d): %s",
                          pretty, subject_buf, issuer_buf, depth, X509_verify_cert_error_string(error));
                return preverify_ok;
        }

        log_level = determine_verification_log_level(m, &preverify_ok);

        log_full(log_level, "TLS: Failed to verify certificate of server=%s (certificate: subject='%s' issuer='%s' depth=%d)%s: %s",
                            pretty, subject_buf, issuer_buf, depth,
                            preverify_ok ? ", ignoring" : "",
                            X509_verify_cert_error_string(error));

        return preverify_ok;
}
