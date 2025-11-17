#ifndef CAPABILITY_HPP
#define CAPABILITY_HPP

#if defined(HAVE_LIBCAPNG)
#include <stdexcept>
#include <boost/log/trivial.hpp>
#include <cap-ng.h>

namespace CapabilityManagment {
    void check_for_capabilites();
    void drop_capabilies();
    void drop_all_capabilies();
}

#endif

#endif
