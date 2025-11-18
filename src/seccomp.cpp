#include "seccomp.hpp"

#ifdef HAVE_SECCOMP

SeccompFilterContext::SeccompFilterContext(uint32_t def_action) :
    ctx(seccomp_init(def_action))
{
    if (this->ctx == nullptr)
        throw std::runtime_error("Failed to initialize seccomp.");
}

void SeccompFilterContext::rule_add(uint32_t action, int syscall)
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    seccomp_rule_add(this->ctx, action, syscall, 0);
}

void SeccompFilterContext::allow(int syscall)
{
    this->rule_add(SCMP_ACT_ALLOW, syscall);
}

void SeccompFilterContext::load()
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    if (seccomp_load(this->ctx) != 0)
        throw std::runtime_error("Failed to load seccomp filter.");
}

void SeccompFilterContext::reset(uint32_t def_action)
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    if (seccomp_reset(this->ctx, def_action) != 0)
        throw std::runtime_error("Failed to reset seccomp filter.");
}

void SeccompFilterContext::release()
{
    if (!this->is_useable())
        throw std::runtime_error("seccomp filter context not useable.");

    seccomp_release(this->ctx);
    this->ctx = nullptr;
}

bool SeccompFilterContext::is_useable() const
{
    return this->ctx != nullptr;
}

#endif
