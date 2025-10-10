// SPDX-FileCopyrightText: Copyright (C) 2024 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "postup_commands.hpp"
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/stdio.hpp>

void PostupCommands::add_postup_command(const std::string& command)
{
    this->_postup_commands.push_back(command);
}

void PostupCommands::execute_commands(
    const boost::asio::any_io_executor ex) const
{
    for (const auto& postup_command : this->_postup_commands)
    {
        BOOST_LOG_TRIVIAL(debug)
            << "Execute post up command: " << postup_command << std::endl;
        boost::process::process child(
            ex,
            postup_command,
            {},
            boost::process::process_stdio{
                .in = nullptr, .out = nullptr, .err = nullptr});
        boost::system::error_code ec;
        child.wait(ec);
        BOOST_LOG_TRIVIAL(debug)
            << "Post up command result: " << child.exit_code() << std::endl;
        if (child.exit_code() != 0 || ec)
        {
            if (ec)
            {
                BOOST_LOG_TRIVIAL(fatal)
                    << "Failed to execute post up command: " << ec.message()
                    << std::endl;
            }
            throw std::runtime_error("Failed to execute post up command.");
        }
    }
}
