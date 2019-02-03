#pragma once
#include <emp-tool/utils/block.h>
#include <emp-tool/utils/utils.h>
#include <emp-tool/utils/prg.h>
#include <emp-tool/io/net_io_channel.h>
#include <emp-tool/execution/circuit_execution.h>
#include <emp-tool/execution/protocol_execution.h>
#include <memory>
#include <sstream>
#include <iostream>
#include <vector>
#include <functional>

namespace emp {
constexpr int MAX_PVC_ITERATION = 2;
enum TPCFlag {
    TPCF_SIM_GC = 0x0,
    TPCF_REAL_GC = 0x1,
    TPCF_OT_ONLY = 0x2,
};

enum class State { 
    INIT,
    OT, GC, 
    SENT, RECV
};
// 2pc type
template <typename RT>
struct TPC {
    using T = std::function<RT (const void *, const void *, int flags)>;
};

template <typename RT>
struct Revealer;

template <>
struct Revealer<std::string> {
    static std::string reveal(std::vector<bool> const& bits) {
        std::stringstream bin;
        int length = bits.size();
        for(int i = 0; i < length; ++i)
            bin << (bits[i]? "1" : "0");
        return bin.str();
    }
};

}
