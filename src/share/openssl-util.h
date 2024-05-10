/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static inline char *tls_error_string(int ssl_error, char *buf, size_t count) {
        assert(buf || count == 0);
        if (ssl_error == SSL_ERROR_SSL)
                ERR_error_string_n(ERR_get_error(), buf, count);
        else
                snprintf(buf, count, "SSL_get_error()=%d", ssl_error);
        return buf;
}

#define TLS_ERROR_BUFSIZE 256
#define TLS_ERROR_STRING(error) \
        tls_error_string((error), (char[TLS_ERROR_BUFSIZE]){}, TLS_ERROR_BUFSIZE)


DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SSL*, SSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIO*, BIO_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509*, X509_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO(void *, OPENSSL_free, NULL);
