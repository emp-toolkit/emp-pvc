#pragma once
#include "emp-pvc/hash_array.h"
#include "emp-pvc/free_gc_hash_io.h"

#include <emp-tool/utils/com.h>
#include <emp-tool/gc/halfgate_gen.h>
#include <emp-tool/io/hash_io_channel.h>
#include <emp-tool/execution/protocol_execution.h>
#include <cstring>

namespace emp {
class GCCommitGen : public ProtocolExecution {
public:
    using io_t = FreeGCHashIO;
    using garbler_t = HalfGateGen<io_t>;

    PRG prg;
    PRG prv_prg;
    GCCommitGen(io_t *io, garbler_t *gc, block *seed = nullptr) 
        : ProtocolExecution(ALICE),
          io_(io),
          gc_(gc)
    {
        reseed(seed);
    }

    ~GCCommitGen() {}

    // same order as InternalGen
    void reseed(block *base_seed) {
        PRG rndness(base_seed);
        block sd;
        rndness.random_block(&sd, 1);
        prg.reseed(&sd);

        rndness.random_block(&sd, 1);
        gc_->set_delta(sd);

        rndness.random_block(&sd, 1);
        prv_prg.reseed(&sd);
        /* no ot */
    }

    void feed(block * label, int party, const bool* b, int len) override {
        prv_prg.random_block(label, len);
    }

    void reveal(bool*, int , const block *, int ) override {
    }

    void commit(Decom decom, Com com) {
        uint8_t buf[Hash::DIGEST_SIZE];
        io_->get_digest((char *)&buf[0]);
        block seed;
        prg.random_block(&seed, 1);
        Commitment commiter;
        commiter.prg.reseed(&seed);
        commiter.commit(decom, com, buf, sizeof(buf));

        if (hsh_gc_)
            std::memcpy(hsh_gc_->data(), buf, Hash::DIGEST_SIZE);
    }

    void use(hash_t *h) { hsh_gc_ = h; }

private:
    hash_t *hsh_gc_ = nullptr;
    io_t *io_ = nullptr;
    garbler_t *gc_ = nullptr;
};

} // namespace emp

