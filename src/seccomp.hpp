// SPDX-FileCopyrightText: Copyright (C) 2024 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SECCOMP_HPP
#define SECCOMP_HPP

#ifdef HAVE_SECCOMP

    #include <stdexcept>
    #include <seccomp.h>

class SeccompFilterContext
{
    public:
        SeccompFilterContext(uint32_t def_action);
        void rule_add(uint32_t action, int syscall);
        void allow(int syscall);
        void kill(int syscall);
        void kill_chown();
        void kill_clock();
        void kill_cpu_emulation();
        void kill_debug();
        void kill_others();
        void kill_ipc();
        void kill_keyring();
        void kill_memlock();
        void kill_module();
        void kill_mount();
        void kill_obsolete();
        void kill_privileged();
        void kill_rawio();
        void kill_reboot();
        void kill_resources();
        void kill_setuid();
        void kill_signal();
        void kill_swap();
        void kill_sync();
        void kill_system_service();
        void load();
        void reset(uint32_t def_action);
        void release();
        [[nodiscard]] bool is_useable() const;

    private:
        scmp_filter_ctx ctx;
};

#endif

#endif
