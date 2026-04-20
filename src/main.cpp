// SPDX-FileCopyrightText: Copyright (C) 2024-2026 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include <fstream>
#include <memory>
#include <span>
#include <sstream>
#include <system_error>
#include <stdexcept>
#include <cstdlib>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <boost/version.hpp>
#include "capability_managment.hpp"
#include "capsicum.hpp"
#include "configuration.hpp"
#include "crazytrace.hpp"
#include "landlock.hpp"
#include "nodecontainer.hpp"
#include "posix_wrapper.hpp"
#include "seccomp.hpp"
#include "tun_tap.hpp"

int main(int argc, char * argv[]) // NOLINT(bugprone-exception-escape)
{
    try
    {
#ifdef HAVE_LIBCAPNG
        CapabilityManagment::check_for_capabilites();
        CapabilityManagment::lock();
        CapabilityManagment::drop_capabilies();
#endif
#ifdef HAVE_LANDLOCK
        const LandlockRuleset landlock_ruleset_init(
            LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
                LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
                LANDLOCK_ACCESS_FS_REFER,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);
    #ifdef HAVE_LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
        landlock_ruleset_init.restrict_self(
            LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON);
    #else
        landlock_ruleset_init.restrict_self();
    #endif
#endif

#ifdef HAVE_SECCOMP
        SeccompFilterContext seccomp_context(SCMP_ACT_ALLOW);
        // see also
        // https://lists.boost.org/archives/list/boost-users@lists.boost.org/thread/YJ5RTK25HLPFEZ3XVBBFQDJOSPIIOBNA/
        // and https://sourceforge.net/p/asio/mailman/message/59260797/
        // due to complexity use seccomp blacklist
        seccomp_context.kill_chown();
        seccomp_context.kill_clock();
        seccomp_context.kill_cpu_emulation();
        seccomp_context.kill_debug();
        seccomp_context.kill_others();
        seccomp_context.kill_ipc();
        seccomp_context.kill_keyring();
        seccomp_context.kill_memlock();
        seccomp_context.kill_module();
        seccomp_context.kill_obsolete();
        seccomp_context.kill_privileged();
        seccomp_context.kill_rawio();
        seccomp_context.kill_reboot();
        seccomp_context.kill_resources();
        seccomp_context.kill_setuid();
        seccomp_context.kill_swap();
        seccomp_context.kill_sync();
        seccomp_context.kill_system_service();
        seccomp_context.load();
#endif

        const auto args = std::span(argv, static_cast<std::size_t>(argc));
        if (args.size() != 2)
            throw std::runtime_error("A configuration file must be specified.");

        const std::string filename(args.at(1));
        const crazytrace::Configuration config(filename);
        config.get_log_level().apply();

        BOOST_LOG_TRIVIAL(info)
            << "libtuntap version (compile time): " << TUNTAP_VERSION_MAJOR
            << "." << TUNTAP_VERSION_MINOR;
        const int version = ::tuntap_version();
        const int major = (version >> 8) & 0xFF;
        const int minor = version & 0xFF;
        BOOST_LOG_TRIVIAL(info)
            << "libtuntap version (runtime): " << major << "." << minor;

#if defined(TINS_VERSION_MAJOR) && defined(TINS_VERSION_MINOR) && \
    defined(TINS_VERSION_PATCH)
        BOOST_LOG_TRIVIAL(info)
            << "libtins version (compile time): " << TINS_VERSION_MAJOR << "."
            << TINS_VERSION_MINOR << "." << TINS_VERSION_PATCH;
#endif

        BOOST_LOG_TRIVIAL(info)
            << "Boost version (compile time): " << (BOOST_VERSION / 100'000)
            << "." << (BOOST_VERSION / 100 % 1000) << "."
            << (BOOST_VERSION % 100);

#ifdef HAVE_LIBCAPNG
        BOOST_LOG_TRIVIAL(info) << "libcapng: true";
#else
        BOOST_LOG_TRIVIAL(info) << "libcapng: false";
#endif

#ifdef HAVE_SECCOMP
        BOOST_LOG_TRIVIAL(info) << "seccomp: true";
        const auto * seccomp_ver = seccomp_version();
        BOOST_LOG_TRIVIAL(info)
            << "seccomp version (runtime): " << seccomp_ver->major << "."
            << seccomp_ver->minor << "." << seccomp_ver->micro;
#else
        BOOST_LOG_TRIVIAL(info) << "seccomp: false";
#endif

#ifdef HAVE_LANDLOCK
        BOOST_LOG_TRIVIAL(info) << "Landlock: true";
        BOOST_LOG_TRIVIAL(info)
            << "Landlock ABI version: " << LandlockRuleset::get_abi_version();
#else
        BOOST_LOG_TRIVIAL(info) << "Landlock: false";
#endif

#ifdef HAVE_CAPSICUM
        BOOST_LOG_TRIVIAL(info) << "capsicum: true";
#else
        BOOST_LOG_TRIVIAL(info) << "capsicum: false";
#endif

        const std::shared_ptr<crazytrace::NodeContainer> nodecontainer =
            config.get_node_container();

        std::ostringstream nodes_verbose;
        nodecontainer->print(nodes_verbose);
        BOOST_LOG_TRIVIAL(info) << nodes_verbose.str();

        constexpr std::size_t mtu = 1500;
        BOOST_LOG_TRIVIAL(debug) << "Create TUN device.";
        tun_tap_device::tun_tap dev(config.get_device_name(),
                                    tun_tap_device::tun_tap_mode::tap);
        BOOST_LOG_TRIVIAL(debug) << "Set MTU to " << mtu << ".";
        dev.set_mtu(mtu);
        BOOST_LOG_TRIVIAL(debug) << "Set the TUN device up.";
        dev.up();

        const int tap_dev_fd = PosixWrapper::dup(dev.native_handler());

        boost::asio::io_context io;
#ifdef BOOST_PROCESS_V1
        config.get_postup_commands().execute_commands();
#else
        config.get_postup_commands().execute_commands(io.get_executor());
#endif

#ifdef HAVE_LIBCAPNG
        CapabilityManagment::drop_all_capabilies();
#endif
#ifdef HAVE_LANDLOCK
        const LandlockRuleset landlock_ruleset_loop(
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
                LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
                LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
                LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_IOCTL_DEV,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL);
        // see also
        // https://lore.kernel.org/landlock/20251119212707.71275873@ciel/T/
    #ifdef HAVE_LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
        landlock_ruleset_init.restrict_self(
            LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON);
    #else
        landlock_ruleset_init.restrict_self();
    #endif
#endif
#ifdef HAVE_SECCOMP
        seccomp_context.kill_signal();
        seccomp_context.load();
        seccomp_context.release();
#endif
#ifdef HAVE_CAPSICUM
        Capsicum::enter();
        Capsicum::limit_stdio();
        Capsicum::limit_rights(dev.native_handler(),
                               CAP_EVENT,
                               CAP_FCNTL,
                               CAP_IOCTL,
                               CAP_READ,
                               CAP_WRITE);
        Capsicum::limit_fcntls(dev.native_handler(),
                               CAP_FCNTL_GETFL | CAP_FCNTL_SETFL);
        Capsicum::limit_ioctls(dev.native_handler(),
                               {FIONBIO, FIONREAD, SIOCATMARK});

        if (Capsicum::in_capability_mode())
        {
            BOOST_LOG_TRIVIAL(info) << "capsicum capabiliy mode: true";
        }
        else
        {
            BOOST_LOG_TRIVIAL(info) << "capsicum capabiliy mode: false";
        }
#endif

        const crazytrace::Crazytrace ct(
            io.get_executor(), tap_dev_fd, nodecontainer);

        io.run();
    }
    catch (const std::exception& e)
    {
        BOOST_LOG_TRIVIAL(fatal) << "Error: " << e.what() << std::endl
                                 << "Exit program.";
        std::exit(EXIT_FAILURE); // NOLINT(concurrency-mt-unsafe)
    }
    catch (...)
    {
        BOOST_LOG_TRIVIAL(fatal) << "Unknown error caught." << std::endl
                                 << "Exit program.";
        std::exit(EXIT_FAILURE); // NOLINT(concurrency-mt-unsafe)
    }
    return EXIT_SUCCESS;
}
