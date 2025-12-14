// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NODEREPLY_HPP
#define NODEREPLY_HPP

#include <iomanip>
#include <ostream>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <tins/tins.h>

namespace crazytrace
{
    enum class NodeReplyType
    {
        NOREPLY, /* No reply is to be sent. */
        ICMP_ECHO_REPLY, /* An ICMP ECHO REPLY packet is sent in response. */
        ICMP_TIME_EXCEEDED_ICMP_ECHO_REQUEST, /* An ICMP TIME EXCEEDED packet is
                                                 sent in response to an ICMP
                                                 ECHO_REQUEST packet. */
        ICMP_PORT_UNREACHABLE, /* An ICMP PORT UNREACHABLE packet is sent in
                                  response. */
        ICMP_TIME_EXCEEDED_UDP, /* An ICMP TIME EXCEEDED packet is sent in
                                   response to an UDP packet. */
        ICMP_NDP /* A neighbor advertisement is sent. */
    };

    class NodeReply
    {
        public:
            explicit NodeReply(NodeReplyType type);
            explicit NodeReply(NodeReplyType type,
                               Tins::HWAddress<6> destination_mac,
                               Tins::IPv6Address destination_address,
                               Tins::HWAddress<6> source_mac,
                               Tins::IPv6Address source_address);

            void set_hoplimit(uint8_t hoplimit);
            void icmp_echo_reply(uint16_t icmp_identifier,
                                 uint16_t icmp_sequence,
                                 const Tins::RawPDU::payload_type& payload);
            void udp_response(const Tins::RawPDU::payload_type& payload,
                              uint16_t udp_dport,
                              uint16_t udp_sport);
            void packet_reassembly(
                Tins::IPv6Address original_destination_address);

            [[nodiscard]] std::string to_packet() const;
            [[nodiscard]] NodeReplyType get_type() const noexcept;

            bool operator==(const NodeReply& other) const;
            friend std::ostream& operator<<(std::ostream& os,
                                            const NodeReply& nodereply);

        private:
            NodeReplyType _type;
            Tins::HWAddress<6> _destination_mac;
            Tins::IPv6Address _destination_address;
            Tins::HWAddress<6> _source_mac;
            Tins::IPv6Address _source_address; /* Also used for ICMP_NDP */

            uint8_t _hoplimit;

            /* ICMP ECHO REPLY */
            uint16_t _icmp_identifier;
            uint16_t _icmp_sequence;

            /* ICMP_PORT_UNREACHABLE */
            Tins::RawPDU::payload_type /* aka std::vector<uint8_t> */ _payload;
            uint16_t _udp_dport;
            uint16_t _udp_sport;

            /* ICMP TIME EXCEEDED */
            Tins::IPv6Address _original_destination_address;
    };

    std::ostream& operator<<(std::ostream& os, const NodeReply& nodereply);
} // namespace crazytrace

#endif
