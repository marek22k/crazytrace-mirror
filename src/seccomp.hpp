#ifndef SECCOMP_HPP
#define SECCOMP_HPP

#ifdef HAVE_SECCOMP

    #include <stdexcept>
    #include <seccomp.h>

class SeccompFilterContext
{
    public:
        SeccompFilterContext(uint32_t def_action);
        void rule_add(uint32_t action, int syscall);
        void allow(int syscall);
        void load();
        void reset(uint32_t def_action);
        void release();
        [[nodiscard]] bool is_useable() const;

    private:
        scmp_filter_ctx ctx;
};

#endif

#endif
