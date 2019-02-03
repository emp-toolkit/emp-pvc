#pragma once
#include <chrono>
#include <emp-tool/utils/utils.h>

struct NamedTimer {
public:
    double usec = 0.; 
    std::string name = "";
    NamedTimer(std::string const& name_ = "") : name(name_) {}

    void start() {
        tp_ = emp::clock_start();
    }

    void stop() {
        usec = emp::time_from(tp_);
    }

private:
    using hc_t = std::chrono::high_resolution_clock;
    using tp_t = std::chrono::time_point<hc_t>;
    tp_t tp_;
};
