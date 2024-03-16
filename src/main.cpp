#include <iostream>
#include <sstream>
#include <memory>
#include <stdexcept>
#include <cstdlib>

#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>

#include <unistd.h>

#include "tun_tap.hpp"
#include "crazytrace.hpp"
#include "nodecontainer.hpp"
#include "configuration.hpp"

int main(int argc, char *argv[]) {
    try {
        if (argc != 2)
            throw std::runtime_error("A configuration file must be specified.");
        
        std::string filename(argv[1]);
        Configuration config(filename);

        boost::log::core::get()->set_filter(
            boost::log::trivial::severity >= config.get_log_level()
        );

        BOOST_LOG_TRIVIAL(info) << "libtuntap version: " << TUNTAP_VERSION_MAJOR << "." << TUNTAP_VERSION_MINOR << std::endl;
        int version = tuntap_version();
        int major = (version >> 8) & 0xFF;
        int minor = version & 0xFF;
        BOOST_LOG_TRIVIAL(info) << "libtuntap version: " << major << "." << minor << std::endl;

        std::shared_ptr<NodeContainer> nodecontainer = config.get_node_container();

        std::ostringstream nodes_verbose;
        nodecontainer->print(nodes_verbose);
        BOOST_LOG_TRIVIAL(info) << nodes_verbose.str();

        boost::asio::io_context io;
        const ::size_t mtu = 1500;
        BOOST_LOG_TRIVIAL(debug) << "Create TUN device." << std::endl;
        tun_tap dev = tun_tap(config.get_device_name(), tun_tap_mode::tap);
        BOOST_LOG_TRIVIAL(debug) << "Set MTU to " << mtu << "." << std::endl;
        dev.set_mtu(1500);
        BOOST_LOG_TRIVIAL(debug) << "Set the TUN device up." << std::endl;
        dev.up();

        Crazytrace ct(io.get_executor(), ::dup(dev.native_handler()), nodecontainer);

        if (config.postup_command_available())
        {
            BOOST_LOG_TRIVIAL(debug) << "Execute post up command." << std::endl;
            int result = std::system(config.get_postup_command().c_str());
            BOOST_LOG_TRIVIAL(debug) << "Post up command result: " << result << std::endl;
            if (result != 0)
                throw std::runtime_error("Failed to execute post up command.");
        }

        io.run();
    } catch (const std::exception &e) {
        BOOST_LOG_TRIVIAL(fatal) << "Error: " << e.what() << std::endl << "Exit program.";
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}
