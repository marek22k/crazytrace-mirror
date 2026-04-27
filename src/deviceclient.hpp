// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DEVICECLIENT_HPP
#define DEVICECLIENT_HPP

#include <array>
#include <functional>
#include <string>
#include <boost/asio.hpp>

namespace tun_tap_device
{
    template<unsigned long BUFFER_SIZE> class DeviceClient
    {
        public:
            explicit DeviceClient(
                const boost::asio::any_io_executor ex,
                int native_handler,
                std::function<void(boost::system::error_code,
                                   std::vector<unsigned char>)> packet_handler,
                std::function<void(boost::system::error_code)> error_handler) :
                _device(ex, native_handler),
                _buffer(),
                _packet_handler(std::move(packet_handler)),
                _error_handler(std::move(error_handler))
            {
                this->read(); // flawfinder: ignore
            }

            void write(const std::vector<unsigned char>& data,
                       const std::function<void(boost::system::error_code,
                                                std::size_t bytes_transferred)>
                           write_handler,
                       const std::function<void(boost::system::error_code)>
                           write_error_handler)
            {
                const auto sdata =
                    std::make_shared<const std::vector<unsigned char>>(data);

                boost::asio::async_write(
                    this->_device,
                    boost::asio::buffer(*sdata),
                    [sdata, write_handler, write_error_handler](
                        boost::system::error_code ec,
                        std::size_t bytes_transferred)
                    {
                        if (ec)
                            write_error_handler(ec);
                        else
                            write_handler(ec, bytes_transferred);
                    });
            }

        private:
            void read() // flawfinder: ignore
            {
                this->_device.async_read_some(
                    boost::asio::buffer(this->_buffer),
                    [this](boost::system::error_code ec,
                           std::size_t bytes_transferred)
                    {
                        if (ec)
                        {
                            this->_error_handler(ec);
                        }
                        else
                        {
                            const std::vector<unsigned char> packet(
                                this->_buffer.data(),
                                std::next(this->_buffer.data(),
                                          static_cast<std::ptrdiff_t>(
                                              bytes_transferred)));
                            this->read(); // flawfinder: ignore

                            this->_packet_handler(ec, packet);
                        }
                    });
            }

            boost::asio::posix::stream_descriptor _device;
            std::array<unsigned char, BUFFER_SIZE> _buffer;
            std::function<void(boost::system::error_code,
                               std::vector<unsigned char>)>
                _packet_handler;
            std::function<void(boost::system::error_code)> _error_handler;
    };
} // namespace tun_tap_device

#endif
