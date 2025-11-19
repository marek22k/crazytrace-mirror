// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef POSTUP_COMMANDS_HPP
#define POSTUP_COMMANDS_HPP

#include <span>
#include <boost/log/trivial.hpp>
#include <boost/process.hpp>

class PostupCommands
{
    public:
        void add_postup_command(const std::string& command);
#ifdef BOOST_PROCESS_V1
        void execute_commands() const;
#else
        void execute_commands(const boost::asio::any_io_executor ex) const;
#endif

    private:
        std::vector<std::string> _postup_commands;
};

#endif
