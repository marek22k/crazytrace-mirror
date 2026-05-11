// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NODEINFO_HPP
#define NODEINFO_HPP

#include <algorithm>
#include <iostream>
#include <limits>
#include <memory>
#include <ostream>
#include <vector>
#include <stdexcept>
#include <cstddef>
#include <cstdint>
#include <tins/tins.h>
#include "randomgenerator.hpp"

namespace crazytrace
{

    class NodeInfo
    {
        public:
            explicit NodeInfo();
            [[nodiscard]] std::vector<std::shared_ptr<NodeInfo>> get_route_to(
                const Tins::IPv6Address& destination_address) const;
            void set_hoplimit(uint8_t hoplimit);
            void set_mac_address(Tins::HWAddress<6> mac_address) noexcept;
            void add_node(std::shared_ptr<NodeInfo> node);
            void add_address(Tins::IPv6Address address);
            [[nodiscard]] uint8_t get_hoplimit() const noexcept;
            [[nodiscard]] bool has_address(const Tins::IPv6Address& address);
            [[nodiscard]] const Tins::HWAddress<6>&
                get_mac_address() const noexcept;
            [[nodiscard]] const Tins::IPv6Address& get_address();
            [[nodiscard]] std::size_t max_depth() const;
            void print(std::ostream& os, unsigned int layer = 0) const;

            bool operator==(const NodeInfo& other) const;
            friend std::ostream& operator<<(std::ostream& os,
                                            NodeInfo const & nodeinfo);

        private:
            std::vector<Tins::IPv6Address> _addresses;
            Tins::HWAddress<6> _mac_address;
            uint8_t _hoplimit;
            std::vector<std::shared_ptr<NodeInfo>> _nodes;
            RandomGenerator _randomgenerator;
            bool _addressadded;
    };

    std::ostream& operator<<(std::ostream& os, NodeInfo const & nodeinfo);
} // namespace crazytrace

#endif
