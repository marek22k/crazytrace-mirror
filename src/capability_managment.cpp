#include "capability_managment.hpp"

#if defined(HAVE_LIBCAPNG)

void CapabilityManagment::check_for_capabilites()
{
    if (!capng_have_capability(CAPNG_PERMITTED, CAP_NET_ADMIN))
        throw std::runtime_error("Missing CAP_NET_ADMIN capability.");

    BOOST_LOG_TRIVIAL(debug) << "CAP_NET_ADMIN capability available.";

    if (!capng_have_capability(CAPNG_PERMITTED, CAP_SETPCAP))
        throw std::runtime_error("Missing CAP_SETPCAP capability.");

    BOOST_LOG_TRIVIAL(debug) << "CAP_SETPCAP capability available.";
}

void CapabilityManagment::drop_capabilies()
{
    capng_clear(CAPNG_SELECT_ALL);

    if (capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_NET_ADMIN) != 0)
        throw std::runtime_error(
            "Failed to set effective CAP_NET_ADMIN capability.");
    if (capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_NET_ADMIN) != 0)
        throw std::runtime_error(
            "Failed to set permitted CAP_NET_ADMIN capability.");
    if (capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_NET_ADMIN) != 0)
        throw std::runtime_error(
            "Failed to set bounding set CAP_NET_ADMIN capability.");
    if (capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_SETPCAP) != 0)
        throw std::runtime_error(
            "Failed to set effective CAP_SETPCAP capability.");
    if (capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_SETPCAP) != 0)
        throw std::runtime_error(
            "Failed to set permitted CAP_SETPCAP capability.");
    if (capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_SETPCAP) != 0)
        throw std::runtime_error(
            "Failed to set bounding set CAP_SETPCAP capability.");
    if (capng_apply(CAPNG_SELECT_ALL) != 0)
        throw std::runtime_error("Failed to apply capabilities.");

    BOOST_LOG_TRIVIAL(debug)
        << "All capabilities except CAP_NET_ADMIN and CAP_SETPCAP dropped.";
}

void CapabilityManagment::drop_all_capabilies()
{
    capng_clear(CAPNG_SELECT_ALL);

    if (capng_apply(CAPNG_SELECT_ALL) != 0)
        throw std::runtime_error("Failed to apply capabilities.");

    BOOST_LOG_TRIVIAL(debug) << "All capabilities dropped.";
}

#endif
