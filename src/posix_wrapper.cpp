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

#ifdef HAVE_SETUGID
void PosixWrapper::set_uid(const uid_t uid)
{
    const int result = ::setuid(uid);
    if (result != 0)
    {
        throw std::system_error(
            errno, std::generic_category(), "Failed to set uid.");
    }
}

void PosixWrapper::set_gid(const gid_t gid)
{
    const int result = ::setgid(gid);
    if (result != 0)
    {
        throw std::system_error(
            errno, std::generic_category(), "Failed to set gid.");
    }
}

uid_t PosixWrapper::username_to_uid(const std::string& username)
{
    // This function is called in a single-threaded manner in crazytrace.
    // Therefore, it may be thread-unsafe.
    struct passwd * entry =
        ::getpwnam(username.c_str()); // NOLINT(concurrency-mt-unsafe)
    if (entry == nullptr)
    {
        throw std::system_error(
            errno, std::generic_category(), "Failed to get uid for username.");
    }
    return entry->pw_uid;
}

gid_t PosixWrapper::groupname_to_gid(const std::string& groupname)
{
    // This function is called in a single-threaded manner in crazytrace.
    // Therefore, it may be thread-unsafe.
    struct group * entry =
        ::getgrnam(groupname.c_str()); // NOLINT(concurrency-mt-unsafe)
    if (entry == nullptr)
    {
        throw std::system_error(
            errno, std::generic_category(), "Failed to get gid for groupname.");
    }
    return entry->gr_gid;
}

void PosixWrapper::drop_supplementary_groups()
{
    std::array<gid_t, 0> empty{};
    if (::setgroups(0, empty.data()) != 0)
    {
        throw std::system_error(
            errno, std::generic_category(), "Could not drop supplementary groups.");
    }
}
#endif
