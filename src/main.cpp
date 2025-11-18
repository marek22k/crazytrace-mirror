// SPDX-FileCopyrightText: Copyright (C) 2024 Marek Küthe <m.k@mk16.de>
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
#include <unistd.h>
#include "capability_managment.hpp"
#include "configuration.hpp"
#include "crazytrace.hpp"
#include "nodecontainer.hpp"
#include "seccomp.hpp"
#include "tun_tap.hpp"

int main(int argc, char * argv[])
{
    try
    {
#ifdef HAVE_LIBCAPNG
        CapabilityManagment::check_for_capabilites();
        CapabilityManagment::lock();
        CapabilityManagment::drop_capabilies();
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
        seccomp_context.kill_signal();
        seccomp_context.kill_swap();
        seccomp_context.kill_sync();
        seccomp_context.kill_system_service();
        seccomp_context.load();

        seccomp_context.release();
#endif

        const auto args = std::span(argv, static_cast<std::size_t>(argc));
        if (args.size() != 2)
            throw std::runtime_error("A configuration file must be specified.");

        const std::string filename(args.at(1));
        const Configuration config(filename);
        config.get_log_level().apply();

        BOOST_LOG_TRIVIAL(info) << "libtuntap version: " << TUNTAP_VERSION_MAJOR
                                << "." << TUNTAP_VERSION_MINOR;
        const int version = ::tuntap_version();
        const int major = (version >> 8) & 0xFF;
        const int minor = version & 0xFF;
        BOOST_LOG_TRIVIAL(info)
            << "libtuntap version: " << major << "." << minor;

#if defined(TINS_VERSION_MAJOR) && defined(TINS_VERSION_MINOR) && \
    defined(TINS_VERSION_PATCH)
        BOOST_LOG_TRIVIAL(info)
            << "libtins version: " << TINS_VERSION_MAJOR << "."
            << TINS_VERSION_MINOR << "." << TINS_VERSION_PATCH;
#endif

        const std::shared_ptr<NodeContainer> nodecontainer =
            config.get_node_container();

        std::ostringstream nodes_verbose;
        nodecontainer->print(nodes_verbose);
        BOOST_LOG_TRIVIAL(info) << nodes_verbose.str();

        constexpr std::size_t mtu = 1500;
        BOOST_LOG_TRIVIAL(debug) << "Create TUN device.";
        tun_tap dev(config.get_device_name(), tun_tap_mode::tap);
        BOOST_LOG_TRIVIAL(debug) << "Set MTU to " << mtu << ".";
        dev.set_mtu(mtu);
        BOOST_LOG_TRIVIAL(debug) << "Set the TUN device up.";
        dev.up();

        boost::asio::io_context io;
#ifdef BOOST_PROCESS_V1
        config.get_postup_commands().execute_commands();
#else
        config.get_postup_commands().execute_commands(io.get_executor());
#endif

#ifdef HAVE_LIBCAPNG
        CapabilityManagment::drop_all_capabilies();
#endif

        const Crazytrace ct(
            io.get_executor(), ::dup(dev.native_handler()), nodecontainer);

        io.run();
    }
    catch (const std::exception& e)
    {
        BOOST_LOG_TRIVIAL(fatal) << "Error: " << e.what() << std::endl
                                 << "Exit program.";
        std::exit(EXIT_FAILURE); // NOLINT(concurrency-mt-unsafe)
    }
    return EXIT_SUCCESS;
}
