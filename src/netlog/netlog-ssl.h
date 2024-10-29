/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>

#include "macro.h"

#define VERIFICATION_DEPTH 20

#define EX_DATA_TLSMANAGER 0
#define EX_DATA_PRETTYADDRESS 1

int ssl_verify_certificate_validity(int preverify_ok, X509_STORE_CTX *store);

DEFINE_TRIVIAL_CLEANUP_FUNC(SSL_CTX*, SSL_CTX_free);
