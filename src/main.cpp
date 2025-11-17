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
#include "tun_tap.hpp"

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

int main(int argc, char * argv[])
{
    try
    {
#ifdef HAVE_LIBCAPNG
        CapabilityManagment::check_for_capabilites();
        CapabilityManagment::lock();
        CapabilityManagment::drop_capabilies();
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

        boost::asio::io_context io;
        constexpr std::size_t mtu = 1500;
        BOOST_LOG_TRIVIAL(debug) << "Create TUN device.";
        tun_tap dev(config.get_device_name(), tun_tap_mode::tap);
        BOOST_LOG_TRIVIAL(debug) << "Set MTU to " << mtu << ".";
        dev.set_mtu(mtu);
        BOOST_LOG_TRIVIAL(debug) << "Set the TUN device up.";
        dev.up();

#ifdef BOOST_PROCESS_V1
        config.get_postup_commands().execute_commands();
#else
        config.get_postup_commands().execute_commands(io.get_executor());
#endif

#ifdef HAVE_LIBCAPNG
        CapabilityManagment::drop_all_capabilies();
#endif

#ifdef HAVE_SECCOMP
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (ctx == nullptr)
            throw std::runtime_error("Failed to initialize seccomp.");
        
        int rule_status;
        
        rule_status = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
        if (rule_status != 0)
            throw std::runtime_error("Failed to add rule.");
        
        rule_status = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
        if (rule_status != 0)
            throw std::runtime_error("Failed to add rule.");
        
        rule_status = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
        if (rule_status != 0)
            throw std::runtime_error("Failed to add rule.");
        
        rule_status = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
        if (rule_status != 0)
            throw std::runtime_error("Failed to add rule.");
        
        rule_status = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        if (rule_status != 0)
            throw std::runtime_error("Failed to add rule.");
        
        rule_status = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        if (rule_status != 0)
            throw std::runtime_error("Failed to add rule.");

        int load_status = seccomp_load(ctx);
        if (load_status != 0)
            throw std::runtime_error("Failed to load seccomp filter.");

        seccomp_release(ctx);
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
