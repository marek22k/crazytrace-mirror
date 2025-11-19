// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef CRAZYTRACE_HPP
#define CRAZYTRACE_HPP

#include <memory>
#include <string>
#include <cstdlib>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <tins/tins.h>
#include "deviceclient.hpp"
#include "nodecontainer.hpp"
#include "noderequest.hpp"

class Crazytrace
{
    public:
        explicit Crazytrace(boost::asio::any_io_executor ex,
                            int native_handler,
                            std::shared_ptr<NodeContainer> nodecontainer);

    private:
        void _handle_error(
            const boost::system::error_code& error) const noexcept;
        void _handle_packet(const boost::system::error_code error,
                            const std::string_view packet_data) noexcept;

        std::shared_ptr<NodeContainer> _nodecontainer;
        DeviceClient<1520> _client;
};

#endif
