#pragma once
#include "emp-pvc/common.h"
#include "emp-pvc/pipe_io.h"
#include "emp-pvc/logged-ot.h"
#include "emp-pvc/hash_array.h"
#include "emp-pvc/gc_commit_gen.h"
#include "emp-pvc/internal_eva.h"
#include "emp-pvc/internal_gen.h"
#include "emp-pvc/gc_hash_io.h"
#include "emp-pvc/ecdsa.h"

#include <emp-ot/np.h>
#include <emp-ot/mextension_kos.h>
#include <emp-tool/utils/ThreadPool.h>

#include <memory>
#include <vector>
#include <thread>
#include <iostream>

namespace emp {
class PVCJudge {
public:
    using bytes_t = std::vector<uint8_t>;
    ThreadPool thread_pool;
    PVCJudge() : thread_pool(2) {}

    template <typename RT>
    int judge(std::string const& cert, typename TPC<RT>::T const& circ) 
    {
        std::ifstream fin(cert);
        if (fin.is_open()) {
            int ret = do_duge<RT>(fin, circ);
            fin.close();
            return ret;
        }
        return 1;
    }

    bool check_seed_ot(block *seedA,
                       block const& seedB, 
                       std::vector<uint8_t> const& trans)
    {
        MemIO mio(trans.size());
        std::memcpy(mio.buffer, trans.data(), trans.size());
        mio.size = trans.size();
        mio.cap = trans.size();
        auto gen = [&mio](PipeIO *io) {
            int32_t len = 0;
            mio.recv_data(&len, sizeof(int32_t));
            eb_t eb;
            for (int i = 0; i < len; ++i) {
                mio.recv_eb(&eb, 1); 
                io->send_eb(&eb, 1);
            }

            for (int i = 0; i < len; ++i)
                io->recv_eb(&eb, 1);

            for (int i = 0; i < len; ++i) {
                block res[2];
                mio.recv_data(&res, 2 * sizeof(block));
                io->send_data(&res, 2 * sizeof(block));
            }
        };

        block recv_seed;
        std::vector<uint8_t> sim_trans;
        auto eva = [&recv_seed, &sim_trans](PipeIO *io, block seedB) {
            LoggedOTCO<PipeIO> base_ot(io);
            base_ot.reseed(&seedB);
            bool b = false;
            base_ot.recv(&recv_seed, &b, 1);
            sim_trans.resize(base_ot.log_length());
            base_ot.get_log(sim_trans.data(), sim_trans.size());
        };

        auto pipe = create_pipe(nullptr);
        auto eva_fur = thread_pool.enqueue(eva, pipe.first, seedB);
        auto gen_fur = thread_pool.enqueue(gen, pipe.second);
        destory_pipe(pipe);
        eva_fur.get();
        gen_fur.get();
        if (sim_trans != trans)
            return false;
        if (seedA) 
            *seedA =recv_seed;
        return true;
    }

    bool verify_sign(
                     int32_t j,
                     Com const& com,
                     hash_t const& ot_tx_dgst,
                     block const& seed,
                     std::vector<uint8_t> const& seed_ot_tx,
                     const uint8_t *sig,
                     const int32_t sig_len,
                     ver_key_t vk) const 
    {
        Hash hsher;
        uint8_t buf[1 + sizeof(Com) + sizeof(hash_t) * 3]; 
        buf[0] = (uint8_t)j;
        uint8_t *ptr = &(buf[1]);
        /* Commit */
        std::memcpy(ptr, com, sizeof(Com));
        ptr += sizeof(Com); 
        /* GC OT transcripts */
        std::memcpy(ptr, ot_tx_dgst.data(), sizeof(hash_t));
        ptr += sizeof(hash_t);
        /* seed B hash */
        hsher.hash_once((char *)ptr, &seed, sizeof(block));
        ptr += sizeof(hash_t);
        /* SeedOT transcript */
        hsher.hash_once((char *)ptr, seed_ot_tx.data(), seed_ot_tx.size());
        ptr += sizeof(hash_t);

        int msg_len = std::distance(&buf[0], ptr);
        return ecdsa_verify(sig, sig_len, buf, msg_len, vk);
    }

    template <typename RT>
        void simulate_gc_commit(Com &com,
                                block seedA, 
                                typename TPC<RT>::T const& circ) const
        {
            Decom d;
            simulate_gc_commit<RT>(com, d, nullptr, seedA, circ);
        }

    template <typename RT>
        void simulate_gc_commit(Com &com, Decom &decom,
                                hash_t *dgst,
                                block seedA, 
                                typename TPC<RT>::T const& circ) const
        {
            using io_t = GCHashIO;
            using garbler_t = HalfGateGen<io_t>;
            using protocol_t = GCCommitGen;

            auto io = new io_t(nullptr);
            auto gc = new garbler_t(io);
            auto gen = new protocol_t(io, gc, &seedA);
            CircuitExecution::circ_exec = gc;
            ProtocolExecution::prot_exec = gen;
            if (dgst)
                gen->use(dgst);
            circ(nullptr, nullptr, TPCF_SIM_GC);
            gen->commit(decom, com);
            delete gen;
            delete gc;
            delete io;
        }


    template <typename RT>
        bool verify_gc_commit(block seedA, 
                              typename TPC<RT>::T const& circ,
                              Com const com) const
        {
            Com sim_com;
            simulate_gc_commit<RT>(sim_com, seedA, circ);
            return 0 == std::memcmp(sim_com, com, sizeof(Com));
        }

    template <typename RT>
        void ot_in_the_head(hash_t & h,
                            const block &seedA, const block &seedB,
                            typename TPC<RT>::T const& circ) 
        {
            bytes_t sim_trans;
            int port = std::abs(std::rand());
            port = std::max(port, 8000);
            port = std::min(port, 65535);
            auto eva = [&]() {
                NetIO *nio = new NetIO("127.0.0.1", port, true);
                simulate_eva<NetIO, RT>(nio, seedB, circ);
                delete nio;
            };
            auto gen = [&]() {
                NetIO *nio = new NetIO(nullptr, port, true);
                simulate_gen<NetIO, RT>(nio, &sim_trans, seedA, circ);
                delete nio;
            };
            std::thread eth(eva);
            std::thread gth(gen);
            eth.join();
            gth.join();
            Hash hsh;
            hsh.hash_once(h.data(), sim_trans.data(), sim_trans.size());
        }

    template <typename RT>
        bool ot_in_the_head(const block &seedA, const block &seedB,
                            typename TPC<RT>::T const& circ,
                            hash_t const& ot_dgst) 
        {
            
            hash_t h;
            ot_in_the_head<RT>(h, seedA, seedB, circ);
            return ot_dgst == h;
        }

    template <class IO, typename RT>
        void simulate_eva(IO *io, 
                          block seedB,
                          typename TPC<RT>::T const& circ) const
        {
            using io_t = IO;
            using garbler_t = HalfGateEva<io_t>;
            using protocol_t = InternalEva<io_t>;
            auto gc = std::make_shared<garbler_t>(io);
            auto eva = std::make_shared<protocol_t>(io, gc.get(), &seedB);
            eva->state = State::OT;
            eva->randomized = true;
            CircuitExecution::circ_exec = gc.get();
            ProtocolExecution::prot_exec = eva.get();
            circ(nullptr, nullptr, TPCF_OT_ONLY);
        }

    template <class IO, typename RT>
        void simulate_gen(IO *io, 
                          bytes_t *ot_dig, 
                          block seedA,
                          typename TPC<RT>::T const& cir) const
        {
            using io_t = IO;
            using garbler_t = HalfGateGen<io_t>;
            using protocol_t = InternalGen<io_t, garbler_t, true>;
            auto gc = std::make_shared<garbler_t>(io);
            auto gen = std::make_shared<protocol_t>(io, gc.get(), &seedA);
            gen->state = State::OT;
            CircuitExecution::circ_exec = gc.get();
            ProtocolExecution::prot_exec = gen.get();
            cir(nullptr, nullptr, TPCF_OT_ONLY);
            if (ot_dig)
                *ot_dig = gen->getOTDigest();
        }

    template <typename RT>
        int do_duge(std::istream &in, typename TPC<RT>::T const& circ) 
        {
            int32_t len;
            uint8_t buf0[128];
            /* pk */
            in.read((char *)&len, sizeof(int32_t));
            in.read((char *)&buf0[0], len);
            ver_key_t vk;
            ecdsa_deserialize_ver_key(vk, buf0, len);
            /* index */
            int32_t j;
            in.read((char *)&j, sizeof(int32_t));
            /* ecdsa signature */ 
            int32_t sig_len;
            uint8_t payload[ECDSA_VK_BYTES];
            in.read((char *)&sig_len, sizeof(int32_t));
            in.read((char *)&payload[0], sig_len);
            /* GC commit */
            Com commit;
            in.read(commit, sizeof(Com));
            /* OT transcript */
            in.read((char *)&len, sizeof(int32_t));
            std::vector<uint8_t> ot_tx(len);
            in.read((char *) ot_tx.data(), len);
            hash_t ot_dgst;
            Hash hsher;
            hsher.hash_once((char *)ot_dgst.data(), ot_tx.data(), len);
            /* seedA */
            block seedB;
            in.read((char *)&seedB, sizeof(block));
            /* seed OT transcript */
            in.read((char *)&len, sizeof(int32_t));
            std::vector<uint8_t> seed_ot_tx(len);
            in.read((char *) seed_ot_tx.data(), len);
            /* judging... */
            block seedA;
            printf("checking seed ot |trans| = %zd\n",seed_ot_tx.size());
            if (!check_seed_ot(&seedA, seedB, seed_ot_tx)) {
                std::cerr << "Can not judge due to invalid seed ot transcript.\n";
                return -1;
            }
            printf("verifying sign\n");
            if (!verify_sign(j, commit, ot_dgst, seedB, seed_ot_tx, 
                             payload, sig_len, vk)) {
                std::cerr << "Can not judge due to invalid ecdsa signature.\n";
                return -1;
            }
            printf("verifying gc commit\n");
            if (!verify_gc_commit<RT>(seedA, circ, commit)) {
                std::cerr << "Judge: Alice has cheated due to invalid gc commit.\n";
                return 1; // Alice has cheated.
            }
            printf("verifying ot trans\n");
            if (!ot_in_the_head<RT>(seedA, seedB, circ, ot_dgst)) {
                std::cerr << "Judge: Alice has cheated due to invalid ot transcript.\n";
                return 1; // Alice has cheated.
            }
            std::cerr << "Can not judge, everything seems corret.\n";
            return -1;
        }
};

} // namespace emp
