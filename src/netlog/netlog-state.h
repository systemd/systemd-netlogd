/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

int state_update_cursor(Manager *m);
int state_load_cursor(Manager *m);
