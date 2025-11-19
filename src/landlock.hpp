// SPDX-FileCopyrightText: Copyright (C) 2024 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef LANDLOCK_HPP
#define LANDLOCK_HPP

#ifdef HAVE_LANDLOCK

    #include <stdexcept>
    #include <cstdint>
    #include <linux/landlock.h>

    #ifdef NO_LANDLOCK_CREATE_RULESET
        #include <unistd.h>
        #include <sys/syscall.h>

inline int landlock_create_ruleset(const struct landlock_ruleset_attr * attr,
                                   size_t size,
                                   uint32_t flags)
{
    return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

    #endif

    #ifdef NO_LANDLOCK_ADD_RULE
        #include <unistd.h>
        #include <sys/syscall.h>

inline int landlock_add_rule(int ruleset_fd,
                             enum landlock_rule_type rule_type,
                             const void * rule_attr,
                             uint32_t flags)
{
    return syscall(
        SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

    #endif

    #ifdef NO_LANDLOCK_RESTRICT_SELF
        #include <unistd.h>
        #include <sys/syscall.h>

inline int landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
    return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

    #endif

class LandlockRuleset
{
    public:
        explicit LandlockRuleset(uint64_t handled_access_fr,
                                 uint64_t handled_access_net,
                                 uint64_t scoped);
        void rule_add(uint32_t action, int syscall);
        void restrict_self();

    private:
        int ruleset;
};

#endif

#endif
