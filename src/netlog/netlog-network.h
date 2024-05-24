/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "netlog-manager.h"

int network_send(Manager *m, struct iovec *iovec, unsigned n_iovec);
