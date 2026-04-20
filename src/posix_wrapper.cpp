// SPDX-FileCopyrightText: Copyright (C) 2026 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "posix_wrapper.hpp"

int PosixWrapper::dup(const int oldfd)
{
    const int result = ::dup(oldfd);
    if (result < 0)
    {
        throw std::system_error(errno,
                                std::generic_category(),
                                "Failed to duplicate file descriptor.");
    }
    return result;
}
