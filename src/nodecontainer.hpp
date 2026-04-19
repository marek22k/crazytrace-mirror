// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NODECONTAINER_HPP
#define NODECONTAINER_HPP

#include <algorithm>
#include <iostream>
#include <memory>
#include <ostream>
#include <vector>
#include <boost/log/trivial.hpp>
#include <tins/tins.h>
#include "nodeinfo.hpp"
#include "nodereply.hpp"
#include "noderequest.hpp"

namespace crazytrace
{
    class NodeContainer
    {
        public:
            [[nodiscard]] NodeReply
                get_reply(const crazytrace::NodeRequest& request);
            void add_node(std::shared_ptr<NodeInfo> node);
            [[nodiscard]] std::size_t max_depth() const;

            void print(std::ostream& os) const;
            bool operator==(const crazytrace::NodeContainer& other) const;
            friend std::ostream&
                operator<<(std::ostream& os,
                           const crazytrace::NodeContainer& nodecontainer);

        private:
            [[nodiscard]] std::vector<std::shared_ptr<crazytrace::NodeInfo>>
                get_route_to(
                    const Tins::IPv6Address& destination_address) const;
            std::vector<std::shared_ptr<crazytrace::NodeInfo>> _nodes;
    };

    std::ostream& operator<<(std::ostream& os,
                             const crazytrace::NodeContainer& nodecontainer);
} // namespace crazytrace

#endif
