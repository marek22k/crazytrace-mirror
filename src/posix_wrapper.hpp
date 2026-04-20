// SPDX-FileCopyrightText: Copyright (C) 2026 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef POSIX_WRAPPER
#define POSIX_WRAPPER

#include <string>
#include <system_error>
#include <unistd.h>

namespace PosixWrapper
{
    [[nodiscard]] int dup(const int oldfd);
}

#endif
