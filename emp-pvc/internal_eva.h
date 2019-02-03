#pragma once
#include "emp-pvc/common.h"
#include <emp-tool/utils/prg.h>
#include <emp-ot/ot_extension.h>
#include <emp-ot/mextension_kos.h>
#include <emp-tool/execution/protocol_execution.h>

namespace emp {
template <class IO>
class InternalEva : public ProtocolExecution {
private:
    PRG prv_prg;
public:
    IO *io = nullptr;
    HalfGateEva<IO> *gc;
    MOTExtension_KOS<IO> *ot;
    State state = State::INIT;
    bool randomized = false;
    InternalEva(IO *io_, HalfGateEva<IO> *gc_, 
                block *base_seed = 0) 
        : ProtocolExecution(BOB),
          io(io_),
          gc(gc_),
          ot(new MOTExtension_KOS<IO>(io)) 
    {
        reseed(base_seed);
    }

    void reseed(block *base_seed) {
        PRG rndness(base_seed);
        block sd;
        rndness.random_block(&sd, 1);
        prv_prg.reseed(&sd);

        rndness.random_block(&sd, 1);
        ot->prg.reseed(&sd);

        rndness.random_block(&sd, 1);
        ot->base_ot->prg.reseed(&sd);
        randomized = false;
    }

    ~InternalEva() { delete ot; }

    void feed(block * label, int party, const bool* b, int len) 
    {
        if (state == State::OT && party == ALICE)
            return;
        if (state == State::GC && party == BOB)
            return;

        if (party == ALICE) {
            io->recv_block(label, len);
        } else  {
            if (randomized) {
                bool *bb = new bool[len];
                prv_prg.random_bool(bb, len);
                ot->recv(label, bb, len);
                std::memset(bb, 0x0, len * sizeof(bool));
                delete []bb;
            } else {
                ot->recv(label, b, len);
            }
        }
	}

    void reveal(bool *, int, const block *, int) {
        assert(0);
	}

};
}
