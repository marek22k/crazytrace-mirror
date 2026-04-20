// SPDX-FileCopyrightText: Copyright (C) 2024-2026 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "configuration.hpp"

using namespace crazytrace;

// NOLINTBEGIN(cppcoreguidelines-pro-type-member-init)
// _log_level is initialized in a function that is called directly from the
// constructor. If _log_level cannot be initialized, an error is thrown.
crazytrace::Configuration::Configuration(const std::string& filename) :
    _node_container(std::make_shared<NodeContainer>()),
    _log_level(boost::log::trivial::info)
{
    // NOLINTEND(cppcoreguidelines-pro-type-member-init)
    this->load(filename);
    this->validate_node_depth();
}

void crazytrace::Configuration::load(const std::string& filename)
{
    try
    {
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
        const YAML::Node config = YAML::LoadFile(filename);
        this->load_log_level(config["log_level"]);

        const YAML::Node device_name_node = config["device_name"];
        if (!device_name_node.IsDefined())
            throw std::runtime_error("device name is missing.");
        this->_device_name = device_name_node.as<std::string>();

#ifdef HAVE_SETUGID
        const YAML::Node setugid_node = config["setugid"];
        if (setugid_node.IsDefined())
        {
            const YAML::Node user_node = setugid_node["user"];
            const YAML::Node group_node = setugid_node["group"];
            if (!user_node.IsDefined() || !group_node.IsDefined())
                throw std::runtime_error("user or group is missing.");

            this->_user = user_node.as<std::string>();
            this->_group = group_node.as<std::string>();
        }
#endif

        const YAML::Node post_up_command_node = config["post_up_commands"];
        this->load_postup_commands(post_up_command_node);

        const YAML::Node nodes_config = config["nodes"];
        this->load_nodes(nodes_config, this->_node_container);
        // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
    }
    catch (const YAML::Exception& e)
    {
        BOOST_LOG_TRIVIAL(error)
            << "Failed to load configuration file: " << e.what() << std::endl;
        throw std::runtime_error("Failed to load configuration file: YAML");
    }
}

void crazytrace::Configuration::validate_node_depth() const
{
    const std::size_t max_depth = this->_node_container->max_depth();
    if (max_depth > 255)
    {
        throw std::runtime_error("The nodes are too deep.");
    }
}

void crazytrace::Configuration::load_log_level(const YAML::Node& node)
{
    if (!node.IsDefined())
        return;

    const std::string log_level_string = node.as<std::string>();
    this->_log_level = LogLevel(log_level_string);
}

void crazytrace::Configuration::load_postup_commands(const YAML::Node& node)
{
    if (node.IsDefined())
    {
        if (!node.IsSequence())
            throw std::runtime_error("post up commands must be an array.");

        for (const auto& command_node : node)
        {
            this->_postup_commands.add_postup_command(
                command_node.as<std::string>());
        }
    }
}

template<typename T>
    requires(std::same_as<T, NodeInfo> || std::same_as<T, NodeContainer>)
void crazytrace::Configuration::load_nodes(const YAML::Node& nodes_config,
                                           std::shared_ptr<T> nodes,
                                           bool mac)
{
    if (nodes_config.IsDefined() && !nodes_config.IsNull())
    {
        if (!nodes_config.IsSequence())
            throw std::runtime_error(
                "Failed to load configuration file: Nodes is not a sequence.");

        for (const auto& node_config : nodes_config)
        {
            if (node_config.IsNull())
                continue;

            if (!node_config.IsMap())
                throw std::runtime_error(
                    "Failed to load configuration file: Node is not a map.");

            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
            if (!node_config["addresses"].IsDefined())
                throw std::runtime_error("Failed to load configuration file: "
                                         "Missing addresses attribute.");
            if (!node_config["addresses"].IsSequence())
                throw std::runtime_error("Failed to load configuration file: "
                                         "Addresses is not a sequence.");
            if (mac && !node_config["mac"].IsDefined())
                throw std::runtime_error("Failed to load configuration "
                                         "file: Missing mac attribute.");
            if (!mac && node_config["mac"].IsDefined())
                throw std::runtime_error("Failed to load configuration file: "
                                         "MAC for non-MAC node is defined.");

            const auto node = std::make_shared<NodeInfo>();

            if (mac)
            {
                node->set_mac_address(
                    Tins::HWAddress<6>(node_config["mac"].as<std::string>()));
            }

            for (const YAML::Node addresses_config = node_config["addresses"];
                 const auto& address_config : addresses_config)
            {
                const Tins::IPv6Address ipv6_address =
                    Tins::IPv6Address(address_config.as<std::string>());
                if (!mac && ip_ranges::linklocal_range.contains(ipv6_address))
                    throw std::runtime_error(
                        "Failed to load configuration file: Link-local address "
                        "for non-MAC node defined.");
                node->add_address(ipv6_address);
            }

            if (const YAML::Node hoplimit_config = node_config["hoplimit"];
                hoplimit_config.IsDefined())
                node->set_hoplimit(hoplimit_config.as<uint8_t>());

            load_nodes(node_config["nodes"], node, false);
            nodes->add_node(node);
            // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
        }
    }
}

std::shared_ptr<NodeContainer>
    crazytrace::Configuration::get_node_container() const noexcept
{
    return this->_node_container;
}

LogLevel crazytrace::Configuration::get_log_level() const noexcept
{
    return this->_log_level;
}

const std::string& crazytrace::Configuration::get_device_name() const noexcept
{
    return this->_device_name;
}

const PostupCommands&
    crazytrace::Configuration::get_postup_commands() const noexcept
{
    return this->_postup_commands;
}

#ifdef HAVE_SETUGID
bool crazytrace::Configuration::has_setguid() const noexcept
{
    return this->_user.has_value() && this->_group.has_value();
}

const std::string& crazytrace::Configuration::get_user() const
{
    return this->_user.value();
}

const std::string& crazytrace::Configuration::get_group() const
{
    return this->_group.value();
}
#endif
