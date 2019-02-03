#pragma once
#include "emp-pvc/common.h"
#include "emp-pvc/hash_io.h"
#include <emp-tool/utils/prg.h>
#include <emp-ot/ot_extension.h>
#include <emp-ot/mextension_kos.h>
#include <emp-tool/execution/protocol_execution.h>

#include <memory>

namespace emp {

template <class IO, bool HashOT>
struct OTFactory {};

template <class IO>
struct OTFactory<IO, false> {
    using ot_io_type = IO;
    using ot_type = MOTExtension_KOS<ot_io_type>;
    ot_type* create(IO *io) {
        return new ot_type(io);
    }
    void destory(ot_type *) {}
};

template <class IO>
struct OTFactory<IO, true> {
    using ot_io_type = typename std::conditional<std::is_same<IO, PipeIO>::value,
                                                 PHashedIO, HashedIO>::type;
    using ot_type = MOTExtension_KOS<ot_io_type>;
    ot_type* create(IO *io) {
        if (io)
            return new ot_type(new ot_io_type(io));
        return nullptr;
    }

    void destory(ot_type *ot) {
        if (ot)
            delete ot->io;
    }
};

template <class IO, bool HashOT>
struct DigestGetter {};

template <class IO>
struct DigestGetter<IO, false> {
    inline void digest(IO *, uint8_t *) {
        std::cerr << "No digest is available." << std::endl;
    } // not thing to do
    inline int length(IO *) const { return 0; }
};

template <class IO>
struct DigestGetter<IO, true> {
    inline int length(IO *io) const { 
        return io->count() * Hash::DIGEST_SIZE;
    };

    inline void digest(IO *io, uint8_t *dig) {
        if (!io || !dig)  return;
        io->finalize();
        int cnt = io->count();
        for (int i = 0; i < cnt; ++i) {
            hash_t const& h = io->hsh_array.get(i);
            std::memcpy(dig, h.data(), sizeof(hash_t));
            dig += sizeof(hash_t);
        }
    } 
};

template <class IO, class GC, bool HashOT>
class InternalGen : public ProtocolExecution {
private:
    using ot_io_type = typename OTFactory<IO, HashOT>::ot_io_type;
    using ot_type = typename OTFactory<IO, HashOT>::ot_type;
    PRG prv_prg;
public:
    IO *io;
    std::shared_ptr<ot_type> ot;
    GC *gc;
    PRG prg; 
    State state = State::INIT;

    InternalGen(IO *io_,
                GC *gc_,
                block *base_seed = 0)
        : ProtocolExecution(ALICE),
          io(io_),
          gc(gc_)
    {
        OTFactory<IO, HashOT> factory;
        ot.reset(factory.create(io));
        reseed(base_seed);
    }

    void reseed(block *base_seed) {
        PRG rndness(base_seed);
        block sd;
        rndness.random_block(&sd, 1);
        prg.reseed(&sd);

        rndness.random_block(&sd, 1);
        gc->set_delta(sd);

        rndness.random_block(&sd, 1);
        prv_prg.reseed(&sd);
        //prv_prg.reseed(fix_key); // TODO should use randomness from base_seed

        rndness.random_block(&sd, 1);
        ot->prg.reseed(&sd);

        rndness.random_block(&sd, 1);
        ot->base_ot->prg.reseed(&sd);
    }

    ~InternalGen() { 
        OTFactory<IO, HashOT> factory;
        factory.destory(ot.get());
    }

    std::vector<uint8_t> getOTDigest() {
        DigestGetter<ot_io_type, true> getter;
        std::vector<uint8_t> dig(getter.length(ot->io));
        getter.digest(ot->io, dig.data());
        return dig;
    }

    void feed(block * label, int party, const bool* b, int len) 
    {
        prv_prg.random_block(label, len);
        /* no need to feed alice's input in OT stage */
        if (state == State::OT && party == ALICE)
            return;
        // if (state == State::GC) {
        //     std::string tag = party == ALICE ? "feed ali " : "feed bob ";
        //     for (int i = 0; i < len; ++i)
        //         std::cout << tag << m128i_to_string(label[i]) << "\n";
        // }
        if (state == State::GC && party == BOB)
            return;

        if (party == ALICE) {
            std::vector<block> ones(label, label + len);
            for (int i = 0; i < len; ++i) {
                if (b[i]) 
                    ones[i] = xorBlocks(ones[i], gc->delta);
            }
            io->send_block(ones.data(), len);
        } else {
            std::vector<block> ones(len);
            for (int i = 0; i < len; ++i)
                ones[i] = xorBlocks(label[i], gc->delta);
            ot->send(label, ones.data(), len);
        }
    }

    void reveal(bool *, int , const block *, int) override {
        assert(0);
    }
};

}
