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

        const Crazytrace ct(
            io.get_executor(), ::dup(dev.native_handler()), nodecontainer);

#ifdef HAVE_SECCOMP
        SeccompFilterContext seccomp_context(SCMP_ACT_KILL);

        // see also
        // https://lists.boost.org/archives/list/boost-users@lists.boost.org/thread/YJ5RTK25HLPFEZ3XVBBFQDJOSPIIOBNA/
        // and https://sourceforge.net/p/asio/mailman/message/59260797/
    #if defined(BOOST_ASIO_HAS_IO_URING_AS_DEFAULT)
        BOOST_LOG_TRIVIAL(debug) << "Boost.Asio uses io uring backend";
    #elif defined(BOOST_ASIO_HAS_EPOLL)
        BOOST_LOG_TRIVIAL(debug) << "Boost.Asio uses epoll backend";
        seccomp_context.allow(SCMP_SYS(epoll_create));
        seccomp_context.allow(SCMP_SYS(epoll_create1));
        seccomp_context.allow(SCMP_SYS(epoll_ctl));
        seccomp_context.allow(SCMP_SYS(epoll_wait));
        seccomp_context.allow(SCMP_SYS(epoll_pwait));
        seccomp_context.allow(SCMP_SYS(epoll_pwait2));
    #else
        seccomp_context.allow(SCMP_SYS(select));
    #endif

    #ifdef BOOST_ASIO_HAS_EVENTFD
        BOOST_LOG_TRIVIAL(debug) << "Boost.Asio uses eventfd backend";
        seccomp_context.allow(SCMP_SYS(eventfd));
        seccomp_context.allow(SCMP_SYS(eventfd2));
    #else
        seccomp_context.allow(SCMP_SYS(pipe));
        seccomp_context.allow(SCMP_SYS(pipe2));
    #endif

    #ifdef BOOST_ASIO_HAS_TIMERFD
        BOOST_LOG_TRIVIAL(debug) << "Boost.Asio uses timerfd backend";
        seccomp_context.allow(SCMP_SYS(timerfd_create));
        seccomp_context.allow(SCMP_SYS(timerfd_settime));
        seccomp_context.allow(SCMP_SYS(timerfd_gettime));
    #endif
        seccomp_context.allow(SCMP_SYS(fcntl));
        seccomp_context.allow(SCMP_SYS(read));
        seccomp_context.allow(SCMP_SYS(write));

        seccomp_context.load();

        BOOST_LOG_TRIVIAL(debug) << "Entered into secure state.";
#endif

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
