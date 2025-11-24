#ifndef TINS_EXTENSIONS
#define TINS_EXTENSIONS

#include <tins/tins.h>

const Tins::AddressRange<Tins::IPv6Address>
    linklocal_range("fe80::",
                    "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // fe80::/10

#endif
