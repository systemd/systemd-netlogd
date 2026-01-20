/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netlog-tls.h"

/* TLS implementation now uses common SSL code in netlog-ssl-common.c.
 * All functions are implemented as inline wrappers in netlog-tls.h for
 * backwards compatibility. This file is kept for potential TLS-specific
 * extensions in the future. */
