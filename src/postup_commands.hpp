// SPDX-FileCopyrightText: Copyright (C) 2024 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef POSTUP_COMMANDS_HPP
#define POSTUP_COMMANDS_HPP

#include <span>
#include <boost/log/trivial.hpp>
#ifdef BOOST_PROCESS_V1
    #include <boost/process/v1/child.hpp>
    #include <boost/process/v1/io.hpp>
#else
    #include <boost/process.hpp>
#endif

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
