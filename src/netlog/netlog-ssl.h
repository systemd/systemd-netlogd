/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/ssl.h>

int ssl_verify_certificate_validity(int status, X509_STORE_CTX *store);
