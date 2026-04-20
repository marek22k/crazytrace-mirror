// SPDX-FileCopyrightText: Copyright (C) 2026 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "posix_wrapper.hpp"

int PosixWrapper::dup(const int oldfd)
{
    const int result = ::dup(oldfd);
    if (result < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to duplicate file descriptor.");
    }
    return result;
}

#ifdef HAVE_SETUGID
void PosixWrapper::setuid(const uid_t uid)
{
    const int result = ::setuid(uid);
    if (result != 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to set uid.");
    }
}

void PosixWrapper::setgid(const gid_t uid)
{
    const int result = ::setgid(uid);
    if (result != 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to set gid.");
    }
}

uid_t PosixWrapper::username_to_uid(const std::string& username)
{
    struct passwd * entry = ::getpwnam(username.c_str());
    if (entry == nullptr)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to get uid for username.");
    }
    return entry->pw_uid;
}

gid_t PosixWrapper::groupname_to_gid(const std::string& groupname)
{
    struct group * entry = ::getgrnam(groupname.c_str());
    if (entry == nullptr)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to get gid for groupname.");
    }
    return entry->gr_gid;
}
#endif
