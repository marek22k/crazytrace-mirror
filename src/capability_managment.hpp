#ifndef CAPABILITY_HPP
#define CAPABILITY_HPP

#if defined(HAVE_LIBCAPNG)
    #include <stdexcept>
    #include <cap-ng.h>
    #include <boost/log/trivial.hpp>

namespace CapabilityManagment
{
    void check_for_capabilites();
    void drop_capabilies();
    void drop_all_capabilies();
} // namespace CapabilityManagment

#endif

#endif
