// SPDX-FileCopyrightText: Copyright (C) 2026 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef POSIX_WRAPPER
#define POSIX_WRAPPER

#include <string>
#include <system_error>
#include <unistd.h>

#ifdef HAVE_SETUGID
    #include <array>
    #include <grp.h>
    #include <pwd.h>
#endif

namespace PosixWrapper
{
    [[nodiscard]] int dup(const int oldfd);

#ifdef HAVE_SETUGID
    void set_uid(const uid_t uid);
    void set_gid(const gid_t gid);
    [[nodiscard]] uid_t username_to_uid(const std::string& username);
    [[nodiscard]] gid_t groupname_to_gid(const std::string& groupname);
    void drop_supplementary_groups();
#endif
} // namespace PosixWrapper

#endif
