// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef IP_RANGES_EXTENSIONS
#define IP_RANGES_EXTENSIONS

#include <tins/tins.h>

namespace ip_ranges
{
    const Tins::AddressRange<Tins::IPv6Address>
        linklocal_range = // NOLINT(bugprone-throwing-static-initialization,
                          // cert-err58-cpp)
        Tins::IPv6Address("fe80::") / 10;
}

#endif
