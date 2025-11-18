// SPDX-FileCopyrightText: Copyright (C) 2024 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "seccomp.hpp"

#ifdef HAVE_SECCOMP

SeccompFilterContext::SeccompFilterContext(uint32_t def_action) :
    ctx(seccomp_init(def_action))
{
    if (this->ctx == nullptr)
        throw std::runtime_error("Failed to initialize seccomp.");
}

void SeccompFilterContext::rule_add(uint32_t action, int syscall)
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    seccomp_rule_add(this->ctx, action, syscall, 0);
}

void SeccompFilterContext::allow(int syscall)
{
    this->rule_add(SCMP_ACT_ALLOW, syscall);
}

void SeccompFilterContext::kill(int syscall)
{
    this->rule_add(SCMP_ACT_KILL, syscall);
}

void SeccompFilterContext::kill_chown()
{
    #ifdef SYS_chown
    seccomp_context.kill(SCMP_SYS(chown));
    #endif
    #ifdef SYS_chown32
    seccomp_context.kill(SCMP_SYS(chown32));
    #endif
    #ifdef SYS_fchown
    seccomp_context.kill(SCMP_SYS(fchown));
    #endif
    #ifdef SYS_fchown32
    seccomp_context.kill(SCMP_SYS(fchown32));
    #endif
    #ifdef SYS_fchownat
    seccomp_context.kill(SCMP_SYS(fchownat));
    #endif
    #ifdef SYS_lchown
    seccomp_context.kill(SCMP_SYS(lchown));
    #endif
    #ifdef SYS_lchown32
    seccomp_context.kill(SCMP_SYS(lchown32));
    #endif
}

void SeccompFilterContext::kill_clock()
{
    #ifdef SYS_adjtimex
    seccomp_context.kill(SCMP_SYS(adjtimex));
    #endif
    #ifdef SYS_clock_adjtime
    seccomp_context.kill(SCMP_SYS(clock_adjtime));
    #endif
    #ifdef SYS_clock_settime
    seccomp_context.kill(SCMP_SYS(clock_settime));
    #endif
    #ifdef SYS_settimeofday
    seccomp_context.kill(SCMP_SYS(settimeofday));
    #endif
    #ifdef SYS_stime
    seccomp_context.kill(SCMP_SYS(stime));
    #endif
}

void SeccompFilterContext::kill_cpu_emulation()
{
    #ifdef SYS_modify_ldt
    seccomp_context.kill(SCMP_SYS(modify_ldt));
    #endif
    #ifdef SYS_subpage_prot
    seccomp_context.kill(SCMP_SYS(subpage_prot));
    #endif
    #ifdef SYS_switch_endian
    seccomp_context.kill(SCMP_SYS(switch_endian));
    #endif
    #ifdef SYS_vm86
    seccomp_context.kill(SCMP_SYS(vm86));
    #endif
    #ifdef SYS_vm86old
    seccomp_context.kill(SCMP_SYS(vm86old));
    #endif
}

void SeccompFilterContext::kill_debug()
{
    #ifdef SYS_lookup_dcookie
    seccomp_context.kill(SCMP_SYS(lookup_dcookie));
    #endif
    #ifdef SYS_perf_event_open
    seccomp_context.kill(SCMP_SYS(perf_event_open));
    #endif
    #ifdef SYS_pidfd_getfd
    seccomp_context.kill(SCMP_SYS(pidfd_getfd));
    #endif
    #ifdef SYS_process_vm_writev
    seccomp_context.kill(SCMP_SYS(process_vm_writev));
    #endif
    #ifdef SYS_rtas
    seccomp_context.kill(SCMP_SYS(rtas));
    #endif
    #ifdef SYS_s390_runtime_instr
    seccomp_context.kill(SCMP_SYS(s390_runtime_instr));
    #endif
    #ifdef SYS_sys_debug_setcontext
    seccomp_context.kill(SCMP_SYS(sys_debug_setcontext));
    #endif
}

void SeccompFilterContext::kill_others()
{
    #ifdef SYS_open_by_handle_at
    seccomp_context.kill(SCMP_SYS(open_by_handle_at));
    #endif
    #ifdef SYS_name_to_handle_at
    seccomp_context.kill(SCMP_SYS(name_to_handle_at));
    #endif
    #ifdef SYS_ioprio_set
    seccomp_context.kill(SCMP_SYS(ioprio_set));
    #endif
    #ifdef SYS_ni_syscall
    seccomp_context.kill(SCMP_SYS(ni_syscall));
    #endif
    #ifdef SYS_syslog
    seccomp_context.kill(SCMP_SYS(syslog));
    #endif
    #ifdef SYS_fanotify_init
    seccomp_context.kill(SCMP_SYS(fanotify_init));
    #endif
    #ifdef SYS_add_key
    seccomp_context.kill(SCMP_SYS(add_key));
    #endif
    #ifdef SYS_request_key
    seccomp_context.kill(SCMP_SYS(request_key));
    #endif
    #ifdef SYS_mbind
    seccomp_context.kill(SCMP_SYS(mbind));
    #endif
    #ifdef SYS_migrate_pages
    seccomp_context.kill(SCMP_SYS(migrate_pages));
    #endif
    #ifdef SYS_move_pages
    seccomp_context.kill(SCMP_SYS(move_pages));
    #endif
    #ifdef SYS_keyctl
    seccomp_context.kill(SCMP_SYS(keyctl));
    #endif
    #ifdef SYS_io_setup
    seccomp_context.kill(SCMP_SYS(io_setup));
    #endif
    #ifdef SYS_io_destroy
    seccomp_context.kill(SCMP_SYS(io_destroy));
    #endif
    #ifdef SYS_io_getevents
    seccomp_context.kill(SCMP_SYS(io_getevents));
    #endif
    #ifdef SYS_io_submit
    seccomp_context.kill(SCMP_SYS(io_submit));
    #endif
    #ifdef SYS_io_cancel
    seccomp_context.kill(SCMP_SYS(io_cancel));
    #endif
    #ifdef SYS_remap_file_pages
    seccomp_context.kill(SCMP_SYS(remap_file_pages));
    #endif
    #ifdef SYS_set_mempolicyvmsplice
    seccomp_context.kill(SCMP_SYS(set_mempolicyvmsplice));
    #endif
    #ifdef SYS_userfaultfd
    seccomp_context.kill(SCMP_SYS(userfaultfd));
    #endif
    #ifdef SYS_acct
    seccomp_context.kill(SCMP_SYS(acct));
    #endif
    #ifdef SYS_bpf
    seccomp_context.kill(SCMP_SYS(bpf));
    #endif
    #ifdef SYS_nfsservctl
    seccomp_context.kill(SCMP_SYS(nfsservctl));
    #endif
    #ifdef SYS_setdomainname
    seccomp_context.kill(SCMP_SYS(setdomainname));
    #endif
    #ifdef SYS_sethostname
    seccomp_context.kill(SCMP_SYS(sethostname));
    #endif
    #ifdef SYS_vhangup
    seccomp_context.kill(SCMP_SYS(vhangup));
    #endif
    #ifdef SYS_ptrace
    seccomp_context.kill(SCMP_SYS(ptrace));
    #endif
    #ifdef SYS_personality
    seccomp_context.kill(SCMP_SYS(personality));
    #endif
    #ifdef SYS_process_vm_readv
    seccomp_context.kill(SCMP_SYS(process_vm_readv));
    #endif
}

void SeccompFilterContext::kill_ipc()
{
    /* without pipe, pipe2 */
    #ifdef SYS_ipc
    seccomp_context.kill(SCMP_SYS(ipc));
    #endif
    #ifdef SYS_memfd_create
    seccomp_context.kill(SCMP_SYS(memfd_create));
    #endif
    #ifdef SYS_mq_getsetattr
    seccomp_context.kill(SCMP_SYS(mq_getsetattr));
    #endif
    #ifdef SYS_mq_notify
    seccomp_context.kill(SCMP_SYS(mq_notify));
    #endif
    #ifdef SYS_mq_open
    seccomp_context.kill(SCMP_SYS(mq_open));
    #endif
    #ifdef SYS_mq_timedreceive
    seccomp_context.kill(SCMP_SYS(mq_timedreceive));
    #endif
    #ifdef SYS_mq_timedsend
    seccomp_context.kill(SCMP_SYS(mq_timedsend));
    #endif
    #ifdef SYS_mq_unlink
    seccomp_context.kill(SCMP_SYS(mq_unlink));
    #endif
    #ifdef SYS_msgctl
    seccomp_context.kill(SCMP_SYS(msgctl));
    #endif
    #ifdef SYS_msgget
    seccomp_context.kill(SCMP_SYS(msgget));
    #endif
    #ifdef SYS_msgrcv
    seccomp_context.kill(SCMP_SYS(msgrcv));
    #endif
    #ifdef SYS_msgsnd
    seccomp_context.kill(SCMP_SYS(msgsnd));
    #endif
    #ifdef SYS_process_madvise
    seccomp_context.kill(SCMP_SYS(process_madvise));
    #endif
    #ifdef SYS_process_vm_readv
    seccomp_context.kill(SCMP_SYS(process_vm_readv));
    #endif
    #ifdef SYS_process_vm_writev
    seccomp_context.kill(SCMP_SYS(process_vm_writev));
    #endif
    #ifdef SYS_semctl
    seccomp_context.kill(SCMP_SYS(semctl));
    #endif
    #ifdef SYS_semget
    seccomp_context.kill(SCMP_SYS(semget));
    #endif
    #ifdef SYS_semop
    seccomp_context.kill(SCMP_SYS(semop));
    #endif
    #ifdef SYS_semtimedop
    seccomp_context.kill(SCMP_SYS(semtimedop));
    #endif
    #ifdef SYS_shmat
    seccomp_context.kill(SCMP_SYS(shmat));
    #endif
    #ifdef SYS_shmctl
    seccomp_context.kill(SCMP_SYS(shmctl));
    #endif
    #ifdef SYS_shmdt
    seccomp_context.kill(SCMP_SYS(shmdt));
    #endif
    #ifdef SYS_shmget
    seccomp_context.kill(SCMP_SYS(shmget));
    #endif
}

void SeccompFilterContext::kill_keyring()
{
    #ifdef SYS_add_key
    seccomp_context.kill(SCMP_SYS(add_key));
    #endif
    #ifdef SYS_keyctl
    seccomp_context.kill(SCMP_SYS(keyctl));
    #endif
    #ifdef SYS_request_key
    seccomp_context.kill(SCMP_SYS(request_key));
    #endif
}

void SeccompFilterContext::kill_memlock()
{
    #ifdef SYS_mlock
    seccomp_context.kill(SCMP_SYS(mlock));
    #endif
    #ifdef SYS_mlock2
    seccomp_context.kill(SCMP_SYS(mlock2));
    #endif
    #ifdef SYS_mlockall
    seccomp_context.kill(SCMP_SYS(mlockall));
    #endif
    #ifdef SYS_munlock
    seccomp_context.kill(SCMP_SYS(munlock));
    #endif
    #ifdef SYS_munlockall
    seccomp_context.kill(SCMP_SYS(munlockall));
    #endif
}

void SeccompFilterContext::kill_module()
{
    #ifdef SYS_delete_module
    seccomp_context.kill(SCMP_SYS(delete_module));
    #endif
    #ifdef SYS_finit_module
    seccomp_context.kill(SCMP_SYS(finit_module));
    #endif
    #ifdef SYS_init_module
    seccomp_context.kill(SCMP_SYS(init_module));
    #endif
}

void SeccompFilterContext::kill_mount()
{
    #ifdef SYS_chroot
    seccomp_context.kill(SCMP_SYS(chroot));
    #endif
    #ifdef SYS_fsconfig
    seccomp_context.kill(SCMP_SYS(fsconfig));
    #endif
    #ifdef SYS_fsmount
    seccomp_context.kill(SCMP_SYS(fsmount));
    #endif
    #ifdef SYS_fsopen
    seccomp_context.kill(SCMP_SYS(fsopen));
    #endif
    #ifdef SYS_fspick
    seccomp_context.kill(SCMP_SYS(fspick));
    #endif
    #ifdef SYS_mount
    seccomp_context.kill(SCMP_SYS(mount));
    #endif
    #ifdef SYS_move_mount
    seccomp_context.kill(SCMP_SYS(move_mount));
    #endif
    #ifdef SYS_open_tree
    seccomp_context.kill(SCMP_SYS(open_tree));
    #endif
    #ifdef SYS_pivot_root
    seccomp_context.kill(SCMP_SYS(pivot_root));
    #endif
    #ifdef SYS_umount
    seccomp_context.kill(SCMP_SYS(umount));
    #endif
    #ifdef SYS_umount2
    seccomp_context.kill(SCMP_SYS(umount2));
    #endif
}

void SeccompFilterContext::kill_obsolete()
{
    #ifdef SYS__sysctl
    seccomp_context.kill(SCMP_SYS(_sysctl));
    #endif
    #ifdef SYS_afs_syscall
    seccomp_context.kill(SCMP_SYS(afs_syscall));
    #endif
    #ifdef SYS_bdflush
    seccomp_context.kill(SCMP_SYS(bdflush));
    #endif
    #ifdef SYS_break
    seccomp_context.kill(SCMP_SYS(break));
    #endif
    #ifdef SYS_create_module
    seccomp_context.kill(SCMP_SYS(create_module));
    #endif
    #ifdef SYS_ftime
    seccomp_context.kill(SCMP_SYS(ftime));
    #endif
    #ifdef SYS_get_kernel_syms
    seccomp_context.kill(SCMP_SYS(get_kernel_syms));
    #endif
    #ifdef SYS_getpmsg
    seccomp_context.kill(SCMP_SYS(getpmsg));
    #endif
    #ifdef SYS_gtty
    seccomp_context.kill(SCMP_SYS(gtty));
    #endif
    #ifdef SYS_idle
    seccomp_context.kill(SCMP_SYS(idle));
    #endif
    #ifdef SYS_lock
    seccomp_context.kill(SCMP_SYS(lock));
    #endif
    #ifdef SYS_mpx
    seccomp_context.kill(SCMP_SYS(mpx));
    #endif
    #ifdef SYS_prof
    seccomp_context.kill(SCMP_SYS(prof));
    #endif
    #ifdef SYS_profil
    seccomp_context.kill(SCMP_SYS(profil));
    #endif
    #ifdef SYS_putpmsg
    seccomp_context.kill(SCMP_SYS(putpmsg));
    #endif
    #ifdef SYS_query_module
    seccomp_context.kill(SCMP_SYS(query_module));
    #endif
    #ifdef SYS_security
    seccomp_context.kill(SCMP_SYS(security));
    #endif
    #ifdef SYS_sgetmask
    seccomp_context.kill(SCMP_SYS(sgetmask));
    #endif
    #ifdef SYS_ssetmask
    seccomp_context.kill(SCMP_SYS(ssetmask));
    #endif
    #ifdef SYS_stty
    seccomp_context.kill(SCMP_SYS(stty));
    #endif
    #ifdef SYS_sysfs
    seccomp_context.kill(SCMP_SYS(sysfs));
    #endif
    #ifdef SYS_tuxcall
    seccomp_context.kill(SCMP_SYS(tuxcall));
    #endif
    #ifdef SYS_ulimit
    seccomp_context.kill(SCMP_SYS(ulimit));
    #endif
    #ifdef SYS_uselib
    seccomp_context.kill(SCMP_SYS(uselib));
    #endif
    #ifdef SYS_ustat
    seccomp_context.kill(SCMP_SYS(ustat));
    #endif
    #ifdef SYS_vserver
    seccomp_context.kill(SCMP_SYS(vserver));
    #endif
}

void SeccompFilterContext::kill_privileged()
{
    #ifdef SYS__sysctl
    seccomp_context.kill(SCMP_SYS(_sysctl));
    #endif
    #ifdef SYS_acct
    seccomp_context.kill(SCMP_SYS(acct));
    #endif
    #ifdef SYS_bpf
    seccomp_context.kill(SCMP_SYS(bpf));
    #endif
    #ifdef SYS_capset
    seccomp_context.kill(SCMP_SYS(capset));
    #endif
    #ifdef SYS_chroot
    seccomp_context.kill(SCMP_SYS(chroot));
    #endif
    #ifdef SYS_fanotify_init
    seccomp_context.kill(SCMP_SYS(fanotify_init));
    #endif
    #ifdef SYS_mount
    seccomp_context.kill(SCMP_SYS(mount));
    #endif
    #ifdef SYS_nfsservctl
    seccomp_context.kill(SCMP_SYS(nfsservctl));
    #endif
    #ifdef SYS_open_by_handle_at
    seccomp_context.kill(SCMP_SYS(open_by_handle_at));
    #endif
    #ifdef SYS_pivot_root
    seccomp_context.kill(SCMP_SYS(pivot_root));
    #endif
    #ifdef SYS_quotactl
    seccomp_context.kill(SCMP_SYS(quotactl));
    #endif
    #ifdef SYS_setdomainname
    seccomp_context.kill(SCMP_SYS(setdomainname));
    #endif
    #ifdef SYS_setfsuid
    seccomp_context.kill(SCMP_SYS(setfsuid));
    #endif
    #ifdef SYS_setfsuid32
    seccomp_context.kill(SCMP_SYS(setfsuid32));
    #endif
    #ifdef SYS_setgroups
    seccomp_context.kill(SCMP_SYS(setgroups));
    #endif
    #ifdef SYS_setgroups32
    seccomp_context.kill(SCMP_SYS(setgroups32));
    #endif
    #ifdef SYS_sethostname
    seccomp_context.kill(SCMP_SYS(sethostname));
    #endif
    #ifdef SYS_setresuid
    seccomp_context.kill(SCMP_SYS(setresuid));
    #endif
    #ifdef SYS_setresuid32
    seccomp_context.kill(SCMP_SYS(setresuid32));
    #endif
    #ifdef SYS_setreuid
    seccomp_context.kill(SCMP_SYS(setreuid));
    #endif
    #ifdef SYS_setreuid32
    seccomp_context.kill(SCMP_SYS(setreuid32));
    #endif
    #ifdef SYS_setuid
    seccomp_context.kill(SCMP_SYS(setuid));
    #endif
    #ifdef SYS_setuid32
    seccomp_context.kill(SCMP_SYS(setuid32));
    #endif
    #ifdef SYS_umount2
    seccomp_context.kill(SCMP_SYS(umount2));
    #endif
    #ifdef SYS_vhangup
    seccomp_context.kill(SCMP_SYS(vhangup));
    #endif
}

void SeccompFilterContext::kill_rawio()
{
    #ifdef SYS_ioperm
    seccomp_context.kill(SCMP_SYS(ioperm));
    #endif
    #ifdef SYS_iopl
    seccomp_context.kill(SCMP_SYS(iopl));
    #endif
    #ifdef SYS_pciconfig_iobase
    seccomp_context.kill(SCMP_SYS(pciconfig_iobase));
    #endif
    #ifdef SYS_pciconfig_read
    seccomp_context.kill(SCMP_SYS(pciconfig_read));
    #endif
    #ifdef SYS_pciconfig_write
    seccomp_context.kill(SCMP_SYS(pciconfig_write));
    #endif
    #ifdef SYS_s390_pci_mmio_read
    seccomp_context.kill(SCMP_SYS(s390_pci_mmio_read));
    #endif
    #ifdef SYS_s390_pci_mmio_write
    seccomp_context.kill(SCMP_SYS(s390_pci_mmio_write));
    #endif
}

void SeccompFilterContext::kill_reboot()
{
    #ifdef SYS_kexec_load
    seccomp_context.kill(SCMP_SYS(kexec_load));
    #endif
    #ifdef SYS_kexec_file_load
    seccomp_context.kill(SCMP_SYS(kexec_file_load));
    #endif
    #ifdef SYS_reboot
    seccomp_context.kill(SCMP_SYS(reboot));
    #endif
}

void SeccompFilterContext::kill_resources()
{
    #ifdef SYS_ioprio_set
    seccomp_context.kill(SCMP_SYS(ioprio_set));
    #endif
    #ifdef SYS_mbind
    seccomp_context.kill(SCMP_SYS(mbind));
    #endif
    #ifdef SYS_migrate_pages
    seccomp_context.kill(SCMP_SYS(migrate_pages));
    #endif
    #ifdef SYS_move_pages
    seccomp_context.kill(SCMP_SYS(move_pages));
    #endif
    #ifdef SYS_nice
    seccomp_context.kill(SCMP_SYS(nice));
    #endif
    #ifdef SYS_sched_setaffinity
    seccomp_context.kill(SCMP_SYS(sched_setaffinity));
    #endif
    #ifdef SYS_sched_setattr
    seccomp_context.kill(SCMP_SYS(sched_setattr));
    #endif
    #ifdef SYS_sched_setparam
    seccomp_context.kill(SCMP_SYS(sched_setparam));
    #endif
    #ifdef SYS_sched_setscheduler
    seccomp_context.kill(SCMP_SYS(sched_setscheduler));
    #endif
    #ifdef SYS_set_mempolicy
    seccomp_context.kill(SCMP_SYS(set_mempolicy));
    #endif
}

void SeccompFilterContext::kill_setuid()
{
    #ifdef SYS_setgid
    seccomp_context.kill(SCMP_SYS(setgid));
    #endif
    #ifdef SYS_setgid32
    seccomp_context.kill(SCMP_SYS(setgid32));
    #endif
    #ifdef SYS_setgroups
    seccomp_context.kill(SCMP_SYS(setgroups));
    #endif
    #ifdef SYS_setgroups32
    seccomp_context.kill(SCMP_SYS(setgroups32));
    #endif
    #ifdef SYS_setregid
    seccomp_context.kill(SCMP_SYS(setregid));
    #endif
    #ifdef SYS_setregid32
    seccomp_context.kill(SCMP_SYS(setregid32));
    #endif
    #ifdef SYS_setresgid
    seccomp_context.kill(SCMP_SYS(setresgid));
    #endif
    #ifdef SYS_setresgid32
    seccomp_context.kill(SCMP_SYS(setresgid32));
    #endif
    #ifdef SYS_setresuid
    seccomp_context.kill(SCMP_SYS(setresuid));
    #endif
    #ifdef SYS_setresuid32
    seccomp_context.kill(SCMP_SYS(setresuid32));
    #endif
    #ifdef SYS_setreuid
    seccomp_context.kill(SCMP_SYS(setreuid));
    #endif
    #ifdef SYS_setreuid32
    seccomp_context.kill(SCMP_SYS(setreuid32));
    #endif
    #ifdef SYS_setuid
    seccomp_context.kill(SCMP_SYS(setuid));
    #endif
    #ifdef SYS_setuid32
    seccomp_context.kill(SCMP_SYS(setuid32));
    #endif
}

void SeccompFilterContext::kill_signal()
{
    #ifdef SYS_rt_sigaction
    seccomp_context.kill(SCMP_SYS(rt_sigaction));
    #endif
    #ifdef SYS_rt_sigpending
    seccomp_context.kill(SCMP_SYS(rt_sigpending));
    #endif
    #ifdef SYS_rt_sigprocmask
    seccomp_context.kill(SCMP_SYS(rt_sigprocmask));
    #endif
    #ifdef SYS_rt_sigsuspend
    seccomp_context.kill(SCMP_SYS(rt_sigsuspend));
    #endif
    #ifdef SYS_rt_sigtimedwait
    seccomp_context.kill(SCMP_SYS(rt_sigtimedwait));
    #endif
    #ifdef SYS_sigaction
    seccomp_context.kill(SCMP_SYS(sigaction));
    #endif
    #ifdef SYS_sigaltstack
    seccomp_context.kill(SCMP_SYS(sigaltstack));
    #endif
    #ifdef SYS_signal
    seccomp_context.kill(SCMP_SYS(signal));
    #endif
    #ifdef SYS_signalfd
    seccomp_context.kill(SCMP_SYS(signalfd));
    #endif
    #ifdef SYS_signalfd4
    seccomp_context.kill(SCMP_SYS(signalfd4));
    #endif
    #ifdef SYS_sigpending
    seccomp_context.kill(SCMP_SYS(sigpending));
    #endif
    #ifdef SYS_sigprocmask
    seccomp_context.kill(SCMP_SYS(sigprocmask));
    #endif
    #ifdef SYS_sigsuspend
    seccomp_context.kill(SCMP_SYS(sigsuspend));
    #endif
}

void SeccompFilterContext::kill_swap()
{
    #ifdef SYS_swapon
    seccomp_context.kill(SCMP_SYS(swapon));
    #endif
    #ifdef SYS_swapoff
    seccomp_context.kill(SCMP_SYS(swapoff));
    #endif
}

void SeccompFilterContext::kill_sync()
{
    #ifdef SYS_fdatasync
    seccomp_context.kill(SCMP_SYS(fdatasync));
    #endif
    #ifdef SYS_fsync
    seccomp_context.kill(SCMP_SYS(fsync));
    #endif
    #ifdef SYS_msync
    seccomp_context.kill(SCMP_SYS(msync));
    #endif
    #ifdef SYS_sync
    seccomp_context.kill(SCMP_SYS(sync));
    #endif
    #ifdef SYS_sync_file_range
    seccomp_context.kill(SCMP_SYS(sync_file_range));
    #endif
    #ifdef SYS_sync_file_range2
    seccomp_context.kill(SCMP_SYS(sync_file_range2));
    #endif
    #ifdef SYS_syncfs
    seccomp_context.kill(SCMP_SYS(syncfs));
    #endif
}

void SeccompFilterContext::kill_system_service()
{
    /* without ioctl */
    #ifdef SYS_brk
    seccomp_context.kill(SCMP_SYS(brk));
    #endif
    #ifdef SYS_capget
    seccomp_context.kill(SCMP_SYS(capget));
    #endif
    #ifdef SYS_capset
    seccomp_context.kill(SCMP_SYS(capset));
    #endif
    #ifdef SYS_copy_file_range
    seccomp_context.kill(SCMP_SYS(copy_file_range));
    #endif
    #ifdef SYS_fadvise64
    seccomp_context.kill(SCMP_SYS(fadvise64));
    #endif
    #ifdef SYS_fadvise64_64
    seccomp_context.kill(SCMP_SYS(fadvise64_64));
    #endif
    #ifdef SYS_flock
    seccomp_context.kill(SCMP_SYS(flock));
    #endif
    #ifdef SYS_get_mempolicy
    seccomp_context.kill(SCMP_SYS(get_mempolicy));
    #endif
    #ifdef SYS_getcpu
    seccomp_context.kill(SCMP_SYS(getcpu));
    #endif
    #ifdef SYS_getpriority
    seccomp_context.kill(SCMP_SYS(getpriority));
    #endif
    #ifdef SYS_getrandom
    seccomp_context.kill(SCMP_SYS(getrandom));
    #endif
    #ifdef SYS_ioprio_get
    seccomp_context.kill(SCMP_SYS(ioprio_get));
    #endif
    #ifdef SYS_kcmp
    seccomp_context.kill(SCMP_SYS(kcmp));
    #endif
    #ifdef SYS_madvise
    seccomp_context.kill(SCMP_SYS(madvise));
    #endif
    #ifdef SYS_mprotect
    seccomp_context.kill(SCMP_SYS(mprotect));
    #endif
    #ifdef SYS_mremap
    seccomp_context.kill(SCMP_SYS(mremap));
    #endif
    #ifdef SYS_name_to_handle_at
    seccomp_context.kill(SCMP_SYS(name_to_handle_at));
    #endif
    #ifdef SYS_oldolduname
    seccomp_context.kill(SCMP_SYS(oldolduname));
    #endif
    #ifdef SYS_olduname
    seccomp_context.kill(SCMP_SYS(olduname));
    #endif
    #ifdef SYS_personality
    seccomp_context.kill(SCMP_SYS(personality));
    #endif
    #ifdef SYS_readahead
    seccomp_context.kill(SCMP_SYS(readahead));
    #endif
    #ifdef SYS_readdir
    seccomp_context.kill(SCMP_SYS(readdir));
    #endif
    #ifdef SYS_remap_file_pages
    seccomp_context.kill(SCMP_SYS(remap_file_pages));
    #endif
    #ifdef SYS_sched_get_priority_max
    seccomp_context.kill(SCMP_SYS(sched_get_priority_max));
    #endif
    #ifdef SYS_sched_get_priority_min
    seccomp_context.kill(SCMP_SYS(sched_get_priority_min));
    #endif
    #ifdef SYS_sched_getaffinity
    seccomp_context.kill(SCMP_SYS(sched_getaffinity));
    #endif
    #ifdef SYS_sched_getattr
    seccomp_context.kill(SCMP_SYS(sched_getattr));
    #endif
    #ifdef SYS_sched_getparam
    seccomp_context.kill(SCMP_SYS(sched_getparam));
    #endif
    #ifdef SYS_sched_getscheduler
    seccomp_context.kill(SCMP_SYS(sched_getscheduler));
    #endif
    #ifdef SYS_sched_rr_get_interval
    seccomp_context.kill(SCMP_SYS(sched_rr_get_interval));
    #endif
    #ifdef SYS_sched_yield
    seccomp_context.kill(SCMP_SYS(sched_yield));
    #endif
    #ifdef SYS_sendfile
    seccomp_context.kill(SCMP_SYS(sendfile));
    #endif
    #ifdef SYS_sendfile64
    seccomp_context.kill(SCMP_SYS(sendfile64));
    #endif
    #ifdef SYS_setfsgid
    seccomp_context.kill(SCMP_SYS(setfsgid));
    #endif
    #ifdef SYS_setfsgid32
    seccomp_context.kill(SCMP_SYS(setfsgid32));
    #endif
    #ifdef SYS_setfsuid
    seccomp_context.kill(SCMP_SYS(setfsuid));
    #endif
    #ifdef SYS_setfsuid32
    seccomp_context.kill(SCMP_SYS(setfsuid32));
    #endif
    #ifdef SYS_setpgid
    seccomp_context.kill(SCMP_SYS(setpgid));
    #endif
    #ifdef SYS_setsid
    seccomp_context.kill(SCMP_SYS(setsid));
    #endif
    #ifdef SYS_splice
    seccomp_context.kill(SCMP_SYS(splice));
    #endif
    #ifdef SYS_sysinfo
    seccomp_context.kill(SCMP_SYS(sysinfo));
    #endif
    #ifdef SYS_tee
    seccomp_context.kill(SCMP_SYS(tee));
    #endif
    #ifdef SYS_umask
    seccomp_context.kill(SCMP_SYS(umask));
    #endif
    #ifdef SYS_uname
    seccomp_context.kill(SCMP_SYS(uname));
    #endif
    #ifdef SYS_userfaultfd
    seccomp_context.kill(SCMP_SYS(userfaultfd));
    #endif
    #ifdef SYS_vmsplice
    seccomp_context.kill(SCMP_SYS(vmsplice));
    #endif
}

void SeccompFilterContext::load()
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    if (seccomp_load(this->ctx) != 0)
        throw std::runtime_error("Failed to load seccomp filter.");
}

void SeccompFilterContext::reset(uint32_t def_action)
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    if (seccomp_reset(this->ctx, def_action) != 0)
        throw std::runtime_error("Failed to reset seccomp filter.");
}

void SeccompFilterContext::release()
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    seccomp_release(this->ctx);
    this->ctx = nullptr;
}

bool SeccompFilterContext::is_useable() const
{
    return this->ctx != nullptr;
}

#endif
