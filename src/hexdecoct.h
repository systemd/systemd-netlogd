/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"

char octchar(int x) _const_;
int unoctchar(char c) _const_;

char decchar(int x) _const_;
int undecchar(char c) _const_;

char hexchar(int x) _const_;
int unhexchar(char c) _const_;
