// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "postup_commands.hpp"

void PostupCommands::add_postup_command(const std::string& command)
{
    this->_postup_commands.push_back(command);
}

#ifdef BOOST_PROCESS_V1

void PostupCommands::execute_commands() const
{
    for (const auto& postup_command : this->_postup_commands)
    {
        BOOST_LOG_TRIVIAL(debug)
            << "Execute post up command: " << postup_command << std::endl;
        std::error_code ec;
        boost::process::v1::child child(
            postup_command,
            boost::process::v1::std_out > boost::process::v1::null,
            boost::process::v1::std_err > boost::process::v1::null,
            ec);
        child.wait();
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

#else

void PostupCommands::execute_commands(
    const boost::asio::any_io_executor ex) const
{
    for (const auto& postup_command : this->_postup_commands)
    {
        BOOST_LOG_TRIVIAL(debug)
            << "Execute post up command: " << postup_command << std::endl;
        const boost::process::shell postup_shell(postup_command);
        const auto postup_command_args = std::span(
            postup_shell.argv(), static_cast<std::size_t>(postup_shell.argc()));

        if (postup_command_args.empty())
        {
            throw std::runtime_error("Failed to execute post up command since "
                                     "there is no command to execute.");
        }

        const std::string_view exe(postup_command_argsat.at(0));
        const bool is_path_to_file = exe.contains('/');

        boost::process::process child(
            ex,
            (is_path_to_file ? exe : postup_shell.exe()),
            postup_shell.args(),
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

#endif
