// SPDX-FileCopyrightText: Copyright (C) 2026 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef CAPSICUM_HPP
#define CAPSICUM_HPP

#ifdef HAVE_CAPSICUM

    #include <system_error>
    #include <cerrno>
    #include <cstdint>
    #include <capsicum_helpers.h>
    #include <sys/capsicum.h>

namespace Capsicum
{

    inline void enter()
    {
        if (::caph_enter() != 0)
            throw std::system_error(
                errno,
                std::generic_category(),
                "Failed to enter capability mode");
    }

    inline void limit_stdio()
    {
        if (::caph_limit_stdio() != 0)
            throw std::system_error(
                errno,
                std::generic_category(),
                "Failed to limit stdio");
    }

    inline void limit_fcntls(int fd, uint32_t fcntlrights)
    {
        if (::caph_fcntls_limit(fd, fcntlrights) != 0)
            throw std::system_error(
                errno,
                std::generic_category(),
                "Failed to limit fcntls rights");
    }

    inline void limit_ioctls(int fd, const std::vector<unsigned long>& cmds)
    {
        if (cmds.empty())
            throw std::out_of_range("cmds is empty");
        
        if (::caph_ioctls_limit(fd, cmds.data(), cmds.size()) != 0)
            throw std::system_error(
                errno,
                std::generic_category(),
                "Failed to limit ioctls rights");
    }

    inline bool in_capability_mode()
    {
       return ::cap_sandboxed();
    }

    template<typename... Rights>
    inline void limit_rights(int fd, Rights... rights) {
        cap_rights_t setrights;
        cap_rights_init(&setrights, rights..., 0);
        if (::caph_rights_limit(fd, &setrights) != 0)
            throw std::system_error(
                errno,
                std::generic_category(),
                "Failed to limit rights");
    }
}

#endif

#endif
