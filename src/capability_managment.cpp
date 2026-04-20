// SPDX-FileCopyrightText: Copyright (C) 2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "capability_managment.hpp"

#ifdef HAVE_LIBCAPNG

void CapabilityManagment::lock()
{
    if (::capng_lock() != 0)
        throw std::system_error(
            errno, std::generic_category(), "Failed to lock capabilities");
}

void CapabilityManagment::check_for_capabilites()
{
    if (::capng_have_capability(CAPNG_PERMITTED, CAP_NET_ADMIN) != 1)
        throw std::runtime_error("Missing CAP_NET_ADMIN capability");

    if (::capng_have_capability(CAPNG_PERMITTED, CAP_SETPCAP) != 1)
        throw std::runtime_error("Missing CAP_SETPCAP capability");

    #ifdef HAVE_SETUGID
    if (::capng_have_capability(CAPNG_PERMITTED, CAP_SETUID) != 1)
        throw std::runtime_error("Missing CAP_SETUID capability");

    if (::capng_have_capability(CAPNG_PERMITTED, CAP_SETGID) != 1)
        throw std::runtime_error("Missing CAP_SETUID capability");
    #endif
}

void CapabilityManagment::drop_capabilies()
{
    ::capng_clear(CAPNG_SELECT_ALL);

    if (::capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_NET_ADMIN) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set effective CAP_NET_ADMIN capability");
    if (::capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_NET_ADMIN) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set permitted CAP_NET_ADMIN capability");
    if (::capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_NET_ADMIN) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set bounding set CAP_NET_ADMIN capability");

    // Allow post up commands to have CAP_NET_ADMIN permission
    if (::capng_update(CAPNG_ADD, CAPNG_INHERITABLE, CAP_NET_ADMIN) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set ambient CAP_NET_ADMIN capability");
    if (::capng_update(CAPNG_ADD, CAPNG_AMBIENT, CAP_NET_ADMIN) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set ambient CAP_NET_ADMIN capability");

    if (::capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_SETPCAP) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set effective CAP_SETPCAP capability");
    if (::capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_SETPCAP) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set permitted CAP_SETPCAP capability");
    if (::capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_SETPCAP) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set bounding set CAP_SETPCAP capability");

    #ifdef HAVE_SETUGID
    if (::capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_SETUID) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set effective CAP_SETUID capability");
    if (::capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_SETUID) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set permitted CAP_SETUID capability");
    if (::capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_SETUID) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set bounding set CAP_SETUID capability");

    if (::capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_SETGID) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set effective CAP_SETGID capability");
    if (::capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_SETGID) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set permitted CAP_SETGID capability");
    if (::capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_SETGID) != 0)
        throw std::system_error(
            errno,
            std::generic_category(),
            "Failed to set bounding set CAP_SETGID capability");
    #endif

    if (::capng_apply(CAPNG_SELECT_ALL) != 0)
        throw std::system_error(
            errno, std::generic_category(), "Failed to apply capabilities");
}

void CapabilityManagment::drop_all_capabilies()
{
    ::capng_clear(CAPNG_SELECT_ALL);

    if (::capng_apply(CAPNG_SELECT_ALL) != 0)
        throw std::system_error(
            errno, std::generic_category(), "Failed to apply capabilities");
}

#endif
