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
    // #lizard forgives

    #ifdef SYS_chown
    seccomp_context.kill(SCMP_SYS(chown)); // flawfinder: ignore
    #endif
    #ifdef SYS_chown32
    seccomp_context.kill(SCMP_SYS(chown32)); // flawfinder: ignore
    #endif
    #ifdef SYS_fchown
    seccomp_context.kill(SCMP_SYS(fchown)); // flawfinder: ignore
    #endif
    #ifdef SYS_fchown32
    seccomp_context.kill(SCMP_SYS(fchown32)); // flawfinder: ignore
    #endif
    #ifdef SYS_fchownat
    seccomp_context.kill(SCMP_SYS(fchownat)); // flawfinder: ignore
    #endif
    #ifdef SYS_lchown
    seccomp_context.kill(SCMP_SYS(lchown)); // flawfinder: ignore
    #endif
    #ifdef SYS_lchown32
    seccomp_context.kill(SCMP_SYS(lchown32)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_clock()
{
    // #lizard forgives

    #ifdef SYS_adjtimex
    seccomp_context.kill(SCMP_SYS(adjtimex)); // flawfinder: ignore
    #endif
    #ifdef SYS_clock_adjtime
    seccomp_context.kill(SCMP_SYS(clock_adjtime)); // flawfinder: ignore
    #endif
    #ifdef SYS_clock_settime
    seccomp_context.kill(SCMP_SYS(clock_settime)); // flawfinder: ignore
    #endif
    #ifdef SYS_settimeofday
    seccomp_context.kill(SCMP_SYS(settimeofday)); // flawfinder: ignore
    #endif
    #ifdef SYS_stime
    seccomp_context.kill(SCMP_SYS(stime)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_cpu_emulation()
{
    // #lizard forgives

    #ifdef SYS_modify_ldt
    seccomp_context.kill(SCMP_SYS(modify_ldt)); // flawfinder: ignore
    #endif
    #ifdef SYS_subpage_prot
    seccomp_context.kill(SCMP_SYS(subpage_prot)); // flawfinder: ignore
    #endif
    #ifdef SYS_switch_endian
    seccomp_context.kill(SCMP_SYS(switch_endian)); // flawfinder: ignore
    #endif
    #ifdef SYS_vm86
    seccomp_context.kill(SCMP_SYS(vm86)); // flawfinder: ignore
    #endif
    #ifdef SYS_vm86old
    seccomp_context.kill(SCMP_SYS(vm86old)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_debug()
{
    // #lizard forgives

    #ifdef SYS_lookup_dcookie
    seccomp_context.kill(SCMP_SYS(lookup_dcookie)); // flawfinder: ignore
    #endif
    #ifdef SYS_perf_event_open
    seccomp_context.kill(SCMP_SYS(perf_event_open)); // flawfinder: ignore
    #endif
    #ifdef SYS_pidfd_getfd
    seccomp_context.kill(SCMP_SYS(pidfd_getfd)); // flawfinder: ignore
    #endif
    #ifdef SYS_process_vm_writev
    seccomp_context.kill(SCMP_SYS(process_vm_writev)); // flawfinder: ignore
    #endif
    #ifdef SYS_rtas
    seccomp_context.kill(SCMP_SYS(rtas)); // flawfinder: ignore
    #endif
    #ifdef SYS_s390_runtime_instr
    seccomp_context.kill(SCMP_SYS(s390_runtime_instr)); // flawfinder: ignore
    #endif
    #ifdef SYS_sys_debug_setcontext
    seccomp_context.kill(SCMP_SYS(sys_debug_setcontext)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_others()
{
    // #lizard forgives

    #ifdef SYS_open_by_handle_at
    seccomp_context.kill(SCMP_SYS(open_by_handle_at)); // flawfinder: ignore
    #endif
    #ifdef SYS_name_to_handle_at
    seccomp_context.kill(SCMP_SYS(name_to_handle_at)); // flawfinder: ignore
    #endif
    #ifdef SYS_ioprio_set
    seccomp_context.kill(SCMP_SYS(ioprio_set)); // flawfinder: ignore
    #endif
    #ifdef SYS_ni_syscall
    seccomp_context.kill(SCMP_SYS(ni_syscall)); // flawfinder: ignore
    #endif
    #ifdef SYS_syslog
    seccomp_context.kill(SCMP_SYS(syslog)); // flawfinder: ignore
    #endif
    #ifdef SYS_fanotify_init
    seccomp_context.kill(SCMP_SYS(fanotify_init)); // flawfinder: ignore
    #endif
    #ifdef SYS_add_key
    seccomp_context.kill(SCMP_SYS(add_key)); // flawfinder: ignore
    #endif
    #ifdef SYS_request_key
    seccomp_context.kill(SCMP_SYS(request_key)); // flawfinder: ignore
    #endif
    #ifdef SYS_mbind
    seccomp_context.kill(SCMP_SYS(mbind)); // flawfinder: ignore
    #endif
    #ifdef SYS_migrate_pages
    seccomp_context.kill(SCMP_SYS(migrate_pages)); // flawfinder: ignore
    #endif
    #ifdef SYS_move_pages
    seccomp_context.kill(SCMP_SYS(move_pages)); // flawfinder: ignore
    #endif
    #ifdef SYS_keyctl
    seccomp_context.kill(SCMP_SYS(keyctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_io_setup
    seccomp_context.kill(SCMP_SYS(io_setup)); // flawfinder: ignore
    #endif
    #ifdef SYS_io_destroy
    seccomp_context.kill(SCMP_SYS(io_destroy)); // flawfinder: ignore
    #endif
    #ifdef SYS_io_getevents
    seccomp_context.kill(SCMP_SYS(io_getevents)); // flawfinder: ignore
    #endif
    #ifdef SYS_io_submit
    seccomp_context.kill(SCMP_SYS(io_submit)); // flawfinder: ignore
    #endif
    #ifdef SYS_io_cancel
    seccomp_context.kill(SCMP_SYS(io_cancel)); // flawfinder: ignore
    #endif
    #ifdef SYS_remap_file_pages
    seccomp_context.kill(SCMP_SYS(remap_file_pages)); // flawfinder: ignore
    #endif
    #ifdef SYS_set_mempolicyvmsplice
    seccomp_context.kill(SCMP_SYS(set_mempolicyvmsplice)); // flawfinder: ignore
    #endif
    #ifdef SYS_userfaultfd
    seccomp_context.kill(SCMP_SYS(userfaultfd)); // flawfinder: ignore
    #endif
    #ifdef SYS_acct
    seccomp_context.kill(SCMP_SYS(acct)); // flawfinder: ignore
    #endif
    #ifdef SYS_bpf
    seccomp_context.kill(SCMP_SYS(bpf)); // flawfinder: ignore
    #endif
    #ifdef SYS_nfsservctl
    seccomp_context.kill(SCMP_SYS(nfsservctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_setdomainname
    seccomp_context.kill(SCMP_SYS(setdomainname)); // flawfinder: ignore
    #endif
    #ifdef SYS_sethostname
    seccomp_context.kill(SCMP_SYS(sethostname)); // flawfinder: ignore
    #endif
    #ifdef SYS_vhangup
    seccomp_context.kill(SCMP_SYS(vhangup)); // flawfinder: ignore
    #endif
    #ifdef SYS_ptrace
    seccomp_context.kill(SCMP_SYS(ptrace)); // flawfinder: ignore
    #endif
    #ifdef SYS_personality
    seccomp_context.kill(SCMP_SYS(personality)); // flawfinder: ignore
    #endif
    #ifdef SYS_process_vm_readv
    seccomp_context.kill(SCMP_SYS(process_vm_readv)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_ipc()
{
    // #lizard forgives

    // without pipe, pipe2

    #ifdef SYS_ipc
    seccomp_context.kill(SCMP_SYS(ipc)); // flawfinder: ignore
    #endif
    #ifdef SYS_memfd_create
    seccomp_context.kill(SCMP_SYS(memfd_create)); // flawfinder: ignore
    #endif
    #ifdef SYS_mq_getsetattr
    seccomp_context.kill(SCMP_SYS(mq_getsetattr)); // flawfinder: ignore
    #endif
    #ifdef SYS_mq_notify
    seccomp_context.kill(SCMP_SYS(mq_notify)); // flawfinder: ignore
    #endif
    #ifdef SYS_mq_open
    seccomp_context.kill(SCMP_SYS(mq_open)); // flawfinder: ignore
    #endif
    #ifdef SYS_mq_timedreceive
    seccomp_context.kill(SCMP_SYS(mq_timedreceive)); // flawfinder: ignore
    #endif
    #ifdef SYS_mq_timedsend
    seccomp_context.kill(SCMP_SYS(mq_timedsend)); // flawfinder: ignore
    #endif
    #ifdef SYS_mq_unlink
    seccomp_context.kill(SCMP_SYS(mq_unlink)); // flawfinder: ignore
    #endif
    #ifdef SYS_msgctl
    seccomp_context.kill(SCMP_SYS(msgctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_msgget
    seccomp_context.kill(SCMP_SYS(msgget)); // flawfinder: ignore
    #endif
    #ifdef SYS_msgrcv
    seccomp_context.kill(SCMP_SYS(msgrcv)); // flawfinder: ignore
    #endif
    #ifdef SYS_msgsnd
    seccomp_context.kill(SCMP_SYS(msgsnd)); // flawfinder: ignore
    #endif
    #ifdef SYS_process_madvise
    seccomp_context.kill(SCMP_SYS(process_madvise)); // flawfinder: ignore
    #endif
    #ifdef SYS_process_vm_readv
    seccomp_context.kill(SCMP_SYS(process_vm_readv)); // flawfinder: ignore
    #endif
    #ifdef SYS_process_vm_writev
    seccomp_context.kill(SCMP_SYS(process_vm_writev)); // flawfinder: ignore
    #endif
    #ifdef SYS_semctl
    seccomp_context.kill(SCMP_SYS(semctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_semget
    seccomp_context.kill(SCMP_SYS(semget)); // flawfinder: ignore
    #endif
    #ifdef SYS_semop
    seccomp_context.kill(SCMP_SYS(semop)); // flawfinder: ignore
    #endif
    #ifdef SYS_semtimedop
    seccomp_context.kill(SCMP_SYS(semtimedop)); // flawfinder: ignore
    #endif
    #ifdef SYS_shmat
    seccomp_context.kill(SCMP_SYS(shmat)); // flawfinder: ignore
    #endif
    #ifdef SYS_shmctl
    seccomp_context.kill(SCMP_SYS(shmctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_shmdt
    seccomp_context.kill(SCMP_SYS(shmdt)); // flawfinder: ignore
    #endif
    #ifdef SYS_shmget
    seccomp_context.kill(SCMP_SYS(shmget)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_keyring()
{
    // #lizard forgives

    #ifdef SYS_add_key
    seccomp_context.kill(SCMP_SYS(add_key)); // flawfinder: ignore
    #endif
    #ifdef SYS_keyctl
    seccomp_context.kill(SCMP_SYS(keyctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_request_key
    seccomp_context.kill(SCMP_SYS(request_key)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_memlock()
{
    // #lizard forgives

    #ifdef SYS_mlock
    seccomp_context.kill(SCMP_SYS(mlock)); // flawfinder: ignore
    #endif
    #ifdef SYS_mlock2
    seccomp_context.kill(SCMP_SYS(mlock2)); // flawfinder: ignore
    #endif
    #ifdef SYS_mlockall
    seccomp_context.kill(SCMP_SYS(mlockall)); // flawfinder: ignore
    #endif
    #ifdef SYS_munlock
    seccomp_context.kill(SCMP_SYS(munlock)); // flawfinder: ignore
    #endif
    #ifdef SYS_munlockall
    seccomp_context.kill(SCMP_SYS(munlockall)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_module()
{
    // #lizard forgives

    #ifdef SYS_delete_module
    seccomp_context.kill(SCMP_SYS(delete_module)); // flawfinder: ignore
    #endif
    #ifdef SYS_finit_module
    seccomp_context.kill(SCMP_SYS(finit_module)); // flawfinder: ignore
    #endif
    #ifdef SYS_init_module
    seccomp_context.kill(SCMP_SYS(init_module)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_mount()
{
    // #lizard forgives

    #ifdef SYS_chroot
    seccomp_context.kill(SCMP_SYS(chroot)); // flawfinder: ignore
    #endif
    #ifdef SYS_fsconfig
    seccomp_context.kill(SCMP_SYS(fsconfig)); // flawfinder: ignore
    #endif
    #ifdef SYS_fsmount
    seccomp_context.kill(SCMP_SYS(fsmount)); // flawfinder: ignore
    #endif
    #ifdef SYS_fsopen
    seccomp_context.kill(SCMP_SYS(fsopen)); // flawfinder: ignore
    #endif
    #ifdef SYS_fspick
    seccomp_context.kill(SCMP_SYS(fspick)); // flawfinder: ignore
    #endif
    #ifdef SYS_mount
    seccomp_context.kill(SCMP_SYS(mount)); // flawfinder: ignore
    #endif
    #ifdef SYS_move_mount
    seccomp_context.kill(SCMP_SYS(move_mount)); // flawfinder: ignore
    #endif
    #ifdef SYS_open_tree
    seccomp_context.kill(SCMP_SYS(open_tree)); // flawfinder: ignore
    #endif
    #ifdef SYS_pivot_root
    seccomp_context.kill(SCMP_SYS(pivot_root)); // flawfinder: ignore
    #endif
    #ifdef SYS_umount
    seccomp_context.kill(SCMP_SYS(umount)); // flawfinder: ignore
    #endif
    #ifdef SYS_umount2
    seccomp_context.kill(SCMP_SYS(umount2)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_obsolete()
{
    // #lizard forgives

    #ifdef SYS__sysctl
    seccomp_context.kill(SCMP_SYS(_sysctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_afs_syscall
    seccomp_context.kill(SCMP_SYS(afs_syscall)); // flawfinder: ignore
    #endif
    #ifdef SYS_bdflush
    seccomp_context.kill(SCMP_SYS(bdflush)); // flawfinder: ignore
    #endif
    #ifdef SYS_break
    seccomp_context.kill(SCMP_SYS(break)); // flawfinder: ignore
    #endif
    #ifdef SYS_create_module
    seccomp_context.kill(SCMP_SYS(create_module)); // flawfinder: ignore
    #endif
    #ifdef SYS_ftime
    seccomp_context.kill(SCMP_SYS(ftime)); // flawfinder: ignore
    #endif
    #ifdef SYS_get_kernel_syms
    seccomp_context.kill(SCMP_SYS(get_kernel_syms)); // flawfinder: ignore
    #endif
    #ifdef SYS_getpmsg
    seccomp_context.kill(SCMP_SYS(getpmsg)); // flawfinder: ignore
    #endif
    #ifdef SYS_gtty
    seccomp_context.kill(SCMP_SYS(gtty)); // flawfinder: ignore
    #endif
    #ifdef SYS_idle
    seccomp_context.kill(SCMP_SYS(idle)); // flawfinder: ignore
    #endif
    #ifdef SYS_lock
    seccomp_context.kill(SCMP_SYS(lock)); // flawfinder: ignore
    #endif
    #ifdef SYS_mpx
    seccomp_context.kill(SCMP_SYS(mpx)); // flawfinder: ignore
    #endif
    #ifdef SYS_prof
    seccomp_context.kill(SCMP_SYS(prof)); // flawfinder: ignore
    #endif
    #ifdef SYS_profil
    seccomp_context.kill(SCMP_SYS(profil)); // flawfinder: ignore
    #endif
    #ifdef SYS_putpmsg
    seccomp_context.kill(SCMP_SYS(putpmsg)); // flawfinder: ignore
    #endif
    #ifdef SYS_query_module
    seccomp_context.kill(SCMP_SYS(query_module)); // flawfinder: ignore
    #endif
    #ifdef SYS_security
    seccomp_context.kill(SCMP_SYS(security)); // flawfinder: ignore
    #endif
    #ifdef SYS_sgetmask
    seccomp_context.kill(SCMP_SYS(sgetmask)); // flawfinder: ignore
    #endif
    #ifdef SYS_ssetmask
    seccomp_context.kill(SCMP_SYS(ssetmask)); // flawfinder: ignore
    #endif
    #ifdef SYS_stty
    seccomp_context.kill(SCMP_SYS(stty)); // flawfinder: ignore
    #endif
    #ifdef SYS_sysfs
    seccomp_context.kill(SCMP_SYS(sysfs)); // flawfinder: ignore
    #endif
    #ifdef SYS_tuxcall
    seccomp_context.kill(SCMP_SYS(tuxcall)); // flawfinder: ignore
    #endif
    #ifdef SYS_ulimit
    seccomp_context.kill(SCMP_SYS(ulimit)); // flawfinder: ignore
    #endif
    #ifdef SYS_uselib
    seccomp_context.kill(SCMP_SYS(uselib)); // flawfinder: ignore
    #endif
    #ifdef SYS_ustat
    seccomp_context.kill(SCMP_SYS(ustat)); // flawfinder: ignore
    #endif
    #ifdef SYS_vserver
    seccomp_context.kill(SCMP_SYS(vserver)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_privileged()
{
    // #lizard forgives

    #ifdef SYS__sysctl
    seccomp_context.kill(SCMP_SYS(_sysctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_acct
    seccomp_context.kill(SCMP_SYS(acct)); // flawfinder: ignore
    #endif
    #ifdef SYS_bpf
    seccomp_context.kill(SCMP_SYS(bpf)); // flawfinder: ignore
    #endif
    #ifdef SYS_capset
    seccomp_context.kill(SCMP_SYS(capset)); // flawfinder: ignore
    #endif
    #ifdef SYS_chroot
    seccomp_context.kill(SCMP_SYS(chroot)); // flawfinder: ignore
    #endif
    #ifdef SYS_fanotify_init
    seccomp_context.kill(SCMP_SYS(fanotify_init)); // flawfinder: ignore
    #endif
    #ifdef SYS_mount
    seccomp_context.kill(SCMP_SYS(mount)); // flawfinder: ignore
    #endif
    #ifdef SYS_nfsservctl
    seccomp_context.kill(SCMP_SYS(nfsservctl)); // flawfinder: ignore
    #endif
    #ifdef SYS_open_by_handle_at
    seccomp_context.kill(SCMP_SYS(open_by_handle_at)); // flawfinder: ignore
    #endif
    #ifdef SYS_pivot_root
    seccomp_context.kill(SCMP_SYS(pivot_root)); // flawfinder: ignore
    #endif
    #ifdef SYS_quotactl
    seccomp_context.kill(SCMP_SYS(quotactl)); // flawfinder: ignore
    #endif
    #ifdef SYS_setdomainname
    seccomp_context.kill(SCMP_SYS(setdomainname)); // flawfinder: ignore
    #endif
    #ifdef SYS_setfsuid
    seccomp_context.kill(SCMP_SYS(setfsuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setfsuid32
    seccomp_context.kill(SCMP_SYS(setfsuid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setgroups
    seccomp_context.kill(SCMP_SYS(setgroups)); // flawfinder: ignore
    #endif
    #ifdef SYS_setgroups32
    seccomp_context.kill(SCMP_SYS(setgroups32)); // flawfinder: ignore
    #endif
    #ifdef SYS_sethostname
    seccomp_context.kill(SCMP_SYS(sethostname)); // flawfinder: ignore
    #endif
    #ifdef SYS_setresuid
    seccomp_context.kill(SCMP_SYS(setresuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setresuid32
    seccomp_context.kill(SCMP_SYS(setresuid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setreuid
    seccomp_context.kill(SCMP_SYS(setreuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setreuid32
    seccomp_context.kill(SCMP_SYS(setreuid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setuid
    seccomp_context.kill(SCMP_SYS(setuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setuid32
    seccomp_context.kill(SCMP_SYS(setuid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_umount2
    seccomp_context.kill(SCMP_SYS(umount2)); // flawfinder: ignore
    #endif
    #ifdef SYS_vhangup
    seccomp_context.kill(SCMP_SYS(vhangup)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_rawio()
{
    // #lizard forgives

    #ifdef SYS_ioperm
    seccomp_context.kill(SCMP_SYS(ioperm)); // flawfinder: ignore
    #endif
    #ifdef SYS_iopl
    seccomp_context.kill(SCMP_SYS(iopl)); // flawfinder: ignore
    #endif
    #ifdef SYS_pciconfig_iobase
    seccomp_context.kill(SCMP_SYS(pciconfig_iobase)); // flawfinder: ignore
    #endif
    #ifdef SYS_pciconfig_read
    seccomp_context.kill(SCMP_SYS(pciconfig_read)); // flawfinder: ignore
    #endif
    #ifdef SYS_pciconfig_write
    seccomp_context.kill(SCMP_SYS(pciconfig_write)); // flawfinder: ignore
    #endif
    #ifdef SYS_s390_pci_mmio_read
    seccomp_context.kill(SCMP_SYS(s390_pci_mmio_read)); // flawfinder: ignore
    #endif
    #ifdef SYS_s390_pci_mmio_write
    seccomp_context.kill(SCMP_SYS(s390_pci_mmio_write)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_reboot()
{
    // #lizard forgives

    #ifdef SYS_kexec_load
    seccomp_context.kill(SCMP_SYS(kexec_load)); // flawfinder: ignore
    #endif
    #ifdef SYS_kexec_file_load
    seccomp_context.kill(SCMP_SYS(kexec_file_load)); // flawfinder: ignore
    #endif
    #ifdef SYS_reboot
    seccomp_context.kill(SCMP_SYS(reboot)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_resources()
{
    // #lizard forgives

    #ifdef SYS_ioprio_set
    seccomp_context.kill(SCMP_SYS(ioprio_set)); // flawfinder: ignore
    #endif
    #ifdef SYS_mbind
    seccomp_context.kill(SCMP_SYS(mbind)); // flawfinder: ignore
    #endif
    #ifdef SYS_migrate_pages
    seccomp_context.kill(SCMP_SYS(migrate_pages)); // flawfinder: ignore
    #endif
    #ifdef SYS_move_pages
    seccomp_context.kill(SCMP_SYS(move_pages)); // flawfinder: ignore
    #endif
    #ifdef SYS_nice
    seccomp_context.kill(SCMP_SYS(nice)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_setaffinity
    seccomp_context.kill(SCMP_SYS(sched_setaffinity)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_setattr
    seccomp_context.kill(SCMP_SYS(sched_setattr)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_setparam
    seccomp_context.kill(SCMP_SYS(sched_setparam)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_setscheduler
    seccomp_context.kill(SCMP_SYS(sched_setscheduler)); // flawfinder: ignore
    #endif
    #ifdef SYS_set_mempolicy
    seccomp_context.kill(SCMP_SYS(set_mempolicy)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_setuid()
{
    // #lizard forgives

    #ifdef SYS_setgid
    seccomp_context.kill(SCMP_SYS(setgid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setgid32
    seccomp_context.kill(SCMP_SYS(setgid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setgroups
    seccomp_context.kill(SCMP_SYS(setgroups)); // flawfinder: ignore
    #endif
    #ifdef SYS_setgroups32
    seccomp_context.kill(SCMP_SYS(setgroups32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setregid
    seccomp_context.kill(SCMP_SYS(setregid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setregid32
    seccomp_context.kill(SCMP_SYS(setregid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setresgid
    seccomp_context.kill(SCMP_SYS(setresgid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setresgid32
    seccomp_context.kill(SCMP_SYS(setresgid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setresuid
    seccomp_context.kill(SCMP_SYS(setresuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setresuid32
    seccomp_context.kill(SCMP_SYS(setresuid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setreuid
    seccomp_context.kill(SCMP_SYS(setreuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setreuid32
    seccomp_context.kill(SCMP_SYS(setreuid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setuid
    seccomp_context.kill(SCMP_SYS(setuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setuid32
    seccomp_context.kill(SCMP_SYS(setuid32)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_signal()
{
    // #lizard forgives

    #ifdef SYS_rt_sigaction
    seccomp_context.kill(SCMP_SYS(rt_sigaction)); // flawfinder: ignore
    #endif
    #ifdef SYS_rt_sigpending
    seccomp_context.kill(SCMP_SYS(rt_sigpending)); // flawfinder: ignore
    #endif
    #ifdef SYS_rt_sigprocmask
    seccomp_context.kill(SCMP_SYS(rt_sigprocmask)); // flawfinder: ignore
    #endif
    #ifdef SYS_rt_sigsuspend
    seccomp_context.kill(SCMP_SYS(rt_sigsuspend)); // flawfinder: ignore
    #endif
    #ifdef SYS_rt_sigtimedwait
    seccomp_context.kill(SCMP_SYS(rt_sigtimedwait)); // flawfinder: ignore
    #endif
    #ifdef SYS_sigaction
    seccomp_context.kill(SCMP_SYS(sigaction)); // flawfinder: ignore
    #endif
    #ifdef SYS_sigaltstack
    seccomp_context.kill(SCMP_SYS(sigaltstack)); // flawfinder: ignore
    #endif
    #ifdef SYS_signal
    seccomp_context.kill(SCMP_SYS(signal)); // flawfinder: ignore
    #endif
    #ifdef SYS_signalfd
    seccomp_context.kill(SCMP_SYS(signalfd)); // flawfinder: ignore
    #endif
    #ifdef SYS_signalfd4
    seccomp_context.kill(SCMP_SYS(signalfd4)); // flawfinder: ignore
    #endif
    #ifdef SYS_sigpending
    seccomp_context.kill(SCMP_SYS(sigpending)); // flawfinder: ignore
    #endif
    #ifdef SYS_sigprocmask
    seccomp_context.kill(SCMP_SYS(sigprocmask)); // flawfinder: ignore
    #endif
    #ifdef SYS_sigsuspend
    seccomp_context.kill(SCMP_SYS(sigsuspend)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_swap()
{
    // #lizard forgives

    #ifdef SYS_swapon
    seccomp_context.kill(SCMP_SYS(swapon)); // flawfinder: ignore
    #endif
    #ifdef SYS_swapoff
    seccomp_context.kill(SCMP_SYS(swapoff)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_sync()
{
    // #lizard forgives

    #ifdef SYS_fdatasync
    seccomp_context.kill(SCMP_SYS(fdatasync)); // flawfinder: ignore
    #endif
    #ifdef SYS_fsync
    seccomp_context.kill(SCMP_SYS(fsync)); // flawfinder: ignore
    #endif
    #ifdef SYS_msync
    seccomp_context.kill(SCMP_SYS(msync)); // flawfinder: ignore
    #endif
    #ifdef SYS_sync
    seccomp_context.kill(SCMP_SYS(sync)); // flawfinder: ignore
    #endif
    #ifdef SYS_sync_file_range
    seccomp_context.kill(SCMP_SYS(sync_file_range)); // flawfinder: ignore
    #endif
    #ifdef SYS_sync_file_range2
    seccomp_context.kill(SCMP_SYS(sync_file_range2)); // flawfinder: ignore
    #endif
    #ifdef SYS_syncfs
    seccomp_context.kill(SCMP_SYS(syncfs)); // flawfinder: ignore
    #endif
}

void SeccompFilterContext::kill_system_service()
{
    // #lizard forgives

    // without ioctl

    #ifdef SYS_brk
    seccomp_context.kill(SCMP_SYS(brk)); // flawfinder: ignore
    #endif
    #ifdef SYS_capget
    seccomp_context.kill(SCMP_SYS(capget)); // flawfinder: ignore
    #endif
    #ifdef SYS_capset
    seccomp_context.kill(SCMP_SYS(capset)); // flawfinder: ignore
    #endif
    #ifdef SYS_copy_file_range
    seccomp_context.kill(SCMP_SYS(copy_file_range)); // flawfinder: ignore
    #endif
    #ifdef SYS_fadvise64
    seccomp_context.kill(SCMP_SYS(fadvise64)); // flawfinder: ignore
    #endif
    #ifdef SYS_fadvise64_64
    seccomp_context.kill(SCMP_SYS(fadvise64_64)); // flawfinder: ignore
    #endif
    #ifdef SYS_flock
    seccomp_context.kill(SCMP_SYS(flock)); // flawfinder: ignore
    #endif
    #ifdef SYS_get_mempolicy
    seccomp_context.kill(SCMP_SYS(get_mempolicy)); // flawfinder: ignore
    #endif
    #ifdef SYS_getcpu
    seccomp_context.kill(SCMP_SYS(getcpu)); // flawfinder: ignore
    #endif
    #ifdef SYS_getpriority
    seccomp_context.kill(SCMP_SYS(getpriority)); // flawfinder: ignore
    #endif
    #ifdef SYS_getrandom
    seccomp_context.kill(SCMP_SYS(getrandom)); // flawfinder: ignore
    #endif
    #ifdef SYS_ioprio_get
    seccomp_context.kill(SCMP_SYS(ioprio_get)); // flawfinder: ignore
    #endif
    #ifdef SYS_kcmp
    seccomp_context.kill(SCMP_SYS(kcmp)); // flawfinder: ignore
    #endif
    #ifdef SYS_madvise
    seccomp_context.kill(SCMP_SYS(madvise)); // flawfinder: ignore
    #endif
    #ifdef SYS_mprotect
    seccomp_context.kill(SCMP_SYS(mprotect)); // flawfinder: ignore
    #endif
    #ifdef SYS_mremap
    seccomp_context.kill(SCMP_SYS(mremap)); // flawfinder: ignore
    #endif
    #ifdef SYS_name_to_handle_at
    seccomp_context.kill(SCMP_SYS(name_to_handle_at)); // flawfinder: ignore
    #endif
    #ifdef SYS_oldolduname
    seccomp_context.kill(SCMP_SYS(oldolduname)); // flawfinder: ignore
    #endif
    #ifdef SYS_olduname
    seccomp_context.kill(SCMP_SYS(olduname)); // flawfinder: ignore
    #endif
    #ifdef SYS_personality
    seccomp_context.kill(SCMP_SYS(personality)); // flawfinder: ignore
    #endif
    #ifdef SYS_readahead
    seccomp_context.kill(SCMP_SYS(readahead)); // flawfinder: ignore
    #endif
    #ifdef SYS_readdir
    seccomp_context.kill(SCMP_SYS(readdir)); // flawfinder: ignore
    #endif
    #ifdef SYS_remap_file_pages
    seccomp_context.kill(SCMP_SYS(remap_file_pages)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_get_priority_max
    seccomp_context.kill(
        SCMP_SYS(sched_get_priority_max)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_get_priority_min
    seccomp_context.kill(
        SCMP_SYS(sched_get_priority_min)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_getaffinity
    seccomp_context.kill(SCMP_SYS(sched_getaffinity)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_getattr
    seccomp_context.kill(SCMP_SYS(sched_getattr)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_getparam
    seccomp_context.kill(SCMP_SYS(sched_getparam)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_getscheduler
    seccomp_context.kill(SCMP_SYS(sched_getscheduler)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_rr_get_interval
    seccomp_context.kill(SCMP_SYS(sched_rr_get_interval)); // flawfinder: ignore
    #endif
    #ifdef SYS_sched_yield
    seccomp_context.kill(SCMP_SYS(sched_yield)); // flawfinder: ignore
    #endif
    #ifdef SYS_sendfile
    seccomp_context.kill(SCMP_SYS(sendfile)); // flawfinder: ignore
    #endif
    #ifdef SYS_sendfile64
    seccomp_context.kill(SCMP_SYS(sendfile64)); // flawfinder: ignore
    #endif
    #ifdef SYS_setfsgid
    seccomp_context.kill(SCMP_SYS(setfsgid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setfsgid32
    seccomp_context.kill(SCMP_SYS(setfsgid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setfsuid
    seccomp_context.kill(SCMP_SYS(setfsuid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setfsuid32
    seccomp_context.kill(SCMP_SYS(setfsuid32)); // flawfinder: ignore
    #endif
    #ifdef SYS_setpgid
    seccomp_context.kill(SCMP_SYS(setpgid)); // flawfinder: ignore
    #endif
    #ifdef SYS_setsid
    seccomp_context.kill(SCMP_SYS(setsid)); // flawfinder: ignore
    #endif
    #ifdef SYS_splice
    seccomp_context.kill(SCMP_SYS(splice)); // flawfinder: ignore
    #endif
    #ifdef SYS_sysinfo
    seccomp_context.kill(SCMP_SYS(sysinfo)); // flawfinder: ignore
    #endif
    #ifdef SYS_tee
    seccomp_context.kill(SCMP_SYS(tee)); // flawfinder: ignore
    #endif
    #ifdef SYS_umask
    seccomp_context.kill(SCMP_SYS(umask)); // flawfinder: ignore
    #endif
    #ifdef SYS_uname
    seccomp_context.kill(SCMP_SYS(uname)); // flawfinder: ignore
    #endif
    #ifdef SYS_userfaultfd
    seccomp_context.kill(SCMP_SYS(userfaultfd)); // flawfinder: ignore
    #endif
    #ifdef SYS_vmsplice
    seccomp_context.kill(SCMP_SYS(vmsplice)); // flawfinder: ignore
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

bool SeccompFilterContext::is_useable() const noexcept
{
    return this->ctx != nullptr;
}

#endif
