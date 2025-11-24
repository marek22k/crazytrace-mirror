// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "nodeinfo.hpp"

using namespace crazytrace;

crazytrace::NodeInfo::NodeInfo() :
    _hoplimit(64),
    _randomgenerator(0),
    _addressadded(false)
{
}

int crazytrace::NodeInfo::get_hoplimit() const noexcept
{
    return this->_hoplimit;
}

void crazytrace::NodeInfo::set_mac_address(
    Tins::HWAddress<6> mac_address) noexcept
{
    this->_mac_address = mac_address;
}

const Tins::HWAddress<6>& crazytrace::NodeInfo::get_mac_address() const noexcept
{
    return this->_mac_address;
}

bool crazytrace::NodeInfo::has_address(const Tins::IPv6Address& address)
{
    return std::ranges::binary_search(this->_addresses, address);
}

void crazytrace::NodeInfo::set_hoplimit(int hoplimit)
{
    if (hoplimit < 0 || hoplimit > 255)
        throw std::invalid_argument(
            "Hop limit outside the permitted value range");
    this->_hoplimit = hoplimit;
}

void crazytrace::NodeInfo::add_node(std::shared_ptr<NodeInfo> node)
{
    this->_nodes.push_back(node);
}

void crazytrace::NodeInfo::add_address(Tins::IPv6Address address)
{
    this->_addressadded = true;
    this->_addresses.push_back(address);
}

const Tins::IPv6Address& crazytrace::NodeInfo::get_address()
{
    if (this->_addressadded)
    {
        /* Is called up each time the number of addresses is changed. However,
           it is not called after each address is added to allow multiple
           addresses to be added quickly. */
        std::size_t max_address = this->_addresses.size();
        if (max_address == 0)
            throw std::invalid_argument(
                "Despite adding an address, none is available.");
        max_address--;

        this->_randomgenerator = RandomGenerator(max_address);
        std::ranges::sort(this->_addresses);
        this->_addressadded = false;
    }
    const std::size_t address_number = this->_randomgenerator.generate();
    return this->_addresses.at(address_number);
}

std::size_t crazytrace::NodeInfo::max_depth() const
{
    std::size_t max = 0;
    for (const auto& node : this->_nodes)
    {
        const std::size_t node_depth = node->max_depth();
        max = std::max(max, node_depth);
    }
    return max + 1;
}

std::vector<std::shared_ptr<NodeInfo>> crazytrace::NodeInfo::get_route_to(
    const Tins::IPv6Address& destination_address) const
{
    for (const auto& node : this->_nodes)
    {
        if (node->has_address(destination_address))
        {
            std::vector<std::shared_ptr<NodeInfo>> result;
            result.push_back(node);
            return result;
        }

        std::vector<std::shared_ptr<NodeInfo>> result =
            node->get_route_to(destination_address);
        if (!result.empty())
        {
            result.push_back(node);
            return result;
        }
    }

    return {};
}

void crazytrace::NodeInfo::print(std::ostream& os, int layer) const
{
    const std::string tabs(layer, '\t');

    os << tabs << *this << std::endl;
    if (!this->_nodes.empty())
    {
        os << tabs << "Childs:" << std::endl;
        for (const auto& node : this->_nodes)
        {
            node->print(os, layer + 1);
        }
    }
}

bool crazytrace::NodeInfo::operator==(const NodeInfo& other) const
{
    return this->_addresses == other._addresses &&
           this->_mac_address == other._mac_address &&
           this->_hoplimit == other._hoplimit &&
           std::ranges::equal(this->_nodes, // flawfinder: ignore
                              other._nodes,
                              [](const auto& a, const auto& b)
                              {
                                  return *a == *b;
                              });
}

std::ostream& crazytrace::operator<<(std::ostream& os,
                                     NodeInfo const & nodeinfo)
{
    os << "NodeInfo: hoplimit=" << nodeinfo._hoplimit;
    for (const auto& address : nodeinfo._addresses)
    {
        os << " " << address;
    }
    if (nodeinfo._mac_address != Tins::HWAddress<6>())
    {
        /* Is not empty address? */
        os << " " << nodeinfo._mac_address;
    }

    return os;
}
