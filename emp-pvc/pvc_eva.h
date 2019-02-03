#pragma once
#include "emp-pvc/judge.h"
#include "emp-pvc/common.h"
#include "emp-pvc/pipe_io.h"
#include "emp-pvc/hash_array.h"
#include "emp-pvc/internal_eva.h"
#include "emp-pvc/gc_commit_gen.h"
#include "emp-pvc/ecdsa.h"

#include <emp-ot/np.h>
#include <emp-ot/mextension_kos.h>

#include <deque>
#include <memory>
#include <vector>
#include <thread>
#include <iostream>
namespace emp {
thread_local bool randomized_input = false;
thread_local int itr = 0;

template <typename IO>
class PVCEva: public ProtocolExecution {
private:
    using garbler_t = HalfGateEva<IO>;
    using evaluator_t = InternalEva<IO>;
    using bytes_t = std::vector<uint8_t>;
    using blk_vec_t = std::vector<block>;
    using blk_que_t = std::deque<block>;
    struct sign_st {
        int32_t sig_len;
        uint8_t payload[ECDSA_SIGN_BYTES];
    };
    using sign_t = sign_st[1];

    inline int get_index(int j) const { return std::min(j, num_io_ - 1); }

    const int num_io_;
    std::vector<IO *> io_;
    IO *aux_io_ = nullptr;
    FreeGCHashIO *hash_gc_io_ = nullptr;
    HalfGateEva<FreeGCHashIO> *hashed_gc_ = nullptr;
    std::vector<garbler_t *> gc_;
    std::vector<evaluator_t*> eva_;
    ver_key_t ver_key_;
    Hash hsher;

public:

    explicit PVCEva(std::vector<IO *> iov, IO *aio)
        : ProtocolExecution(BOB),
          num_io_(iov.size()),
          io_(iov),
          aux_io_(aio)
    {
        assert(num_io_ > 0);
        gc_.resize(num_io_);
        eva_.resize(num_io_);
        for (int i = 0; i < num_io_; ++i) {
            gc_[i] = new garbler_t(io_[i]);
            eva_[i] = new evaluator_t(io_[i], gc_[i]);
        }
        hsh_ow_.reserve(1 << 25);
        output_labels_.reserve(1 << 25);
    }

    ~PVCEva() {
        std::memset(seeds_B_, 0, sizeof(seeds_B_));
        for (auto gc : gc_) delete gc;
        for (auto eva : eva_) delete eva;
        if (hash_gc_io_) delete hash_gc_io_;
        if (hashed_gc_) delete hashed_gc_;
    }

    template <typename RT>
    bool run(typename TPC<RT>::T const& circ, const void *bob_input) {
        ot_on_seeds();
        std::thread ot_in_head_th([this, &circ] {
            ot_in_the_head<RT>(circ);
        });
        bool valid = true;
        /* concurrently run small tasks along with real OT */
        std::thread small_tasks([this, &circ, &valid] {
            simulate_gc_commit<RT>(circ); /* simulate gc commit first */
            if (!recv_and_check_circuit_commits()) {
                std::cout << "invalid gc commitment\n";
                valid = false;
            }
            send_seeds_hash();
        });
        run_real_ot<RT>(circ, bob_input);
        int invalid_index = -1;
        small_tasks.join();
        valid = recv_and_check_sign_trans(&invalid_index);
        if (valid) {
            send_witness();
            run_real_gc<RT>(circ, bob_input);
        } else {
            std::cout << "invalid ecdsa sign" << std::endl;
            create_cheated_cert(invalid_index);
            judge_cert<RT>(circ);
            return valid;
        }
        ot_in_head_th.join();
        valid = check_ot_trans(&invalid_index);
        if (!valid) {
            std::cout << "invalid real gc commit" << std::endl;
            create_cheated_cert(invalid_index);
            judge_cert<RT>(circ);
        }
        return valid;
    }

    void feed(block *label, int party, const bool *b, int len)
    {
        if (state == State::GC && party == BOB) {
            assert(input_labels_.size() >= len);
            assert(!randomized_input);
            auto st = input_labels_.begin();
            auto ed = st + len;
            auto tmp = st;
            block *ptr = label;
            while (tmp != ed)
                *ptr++ = *tmp++;
            input_labels_.erase(st, ed);
            return;
        }

        eva_[get_index(itr)]->randomized = randomized_input;
        eva_[get_index(itr)]->feed(label, party, b, len);

        if (state == State::OT && party == BOB && !randomized_input) {
            input_labels_.insert(input_labels_.end(), label, label + len);
        }
    }

    void reveal(bool *b, int party, const block *label, int len)
    {
        assert(state == State::GC);
        if (party == BOB) {
            output_labels_.insert(output_labels_.end(), label, label + len);
        }
    }

    void setup_real_gc(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        setup_exec(j);
        state = State::GC;
        eva_[get_index(j)]->state = state;
        hash_gc_io_ = new FreeGCHashIO(io_[get_index(j)]);
        hashed_gc_ = new HalfGateEva<FreeGCHashIO>(hash_gc_io_);
        CircuitExecution::circ_exec = hashed_gc_;
    }

    void setup_ot(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        setup_exec(j);
        state = State::OT;
        randomized_input = (j != chosen_index_);
        eva_[get_index(j)]->state = state;
    }

    void setup_exec(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        itr = j;
        state = State::INIT;
        randomized_input = false;
        const int idx = get_index(j);
        if (gc_[idx]) delete gc_[idx];
        if (eva_[idx]) delete eva_[idx];
        gc_[idx] = new garbler_t(io_[idx]);
        eva_[idx] = new evaluator_t(io_[idx], gc_[idx], &seeds_B_[j]);
        CircuitExecution::circ_exec = gc_[idx];
        ProtocolExecution::prot_exec = this;
    }

private:
    int       chosen_index_ = 0;   /* 1-of-L. */
    State     state;               /* protocol_execution state */
    uint64_t  label_id = 0;
    PRP       label_prp;
    blk_que_t input_labels_;       /* input labels for the evaluation circuit */
    blk_vec_t output_labels_;
    std::vector<int64_t> hsh_ow_;      /* output labels for the evaluation circuit. */
    std::vector<int64_t> rev_hsh_ow_;         /* hash of output labels recv from Alice.  */
    block     seeds_B_[MAX_PVC_ITERATION];
    block     seeds_A_[MAX_PVC_ITERATION];
    bytes_t   tx_sd_ot_[MAX_PVC_ITERATION];       /* transcript of seeds OT. */
    bytes_t   rev_ot_tx_[MAX_PVC_ITERATION];      /* received OT transcript. */
    hash_t    sim_ot_tx_dgst_[MAX_PVC_ITERATION]; /* digest of the simulated OT transcript. */
    Com       sim_com_[MAX_PVC_ITERATION];        /* simulated gc commit */
    Com       rev_com_[MAX_PVC_ITERATION];        /* received gc commit. */
    sign_t    tx_sign_[MAX_PVC_ITERATION];        /* Alice's sign on whole transcript. */

    /*
     * Run MAX_PVC_ITERATION 1-of-2 OTs on Alices' seeds
     */
    void ot_on_seeds() {
        PRG prg;//("this-is-a-fixed-prg-too");
        prg.random_data(&chosen_index_, sizeof(int));
        chosen_index_ = std::abs(chosen_index_) % MAX_PVC_ITERATION;
        prg.random_block(seeds_B_, MAX_PVC_ITERATION);
        LoggedOTCO<IO> logOT(nullptr);
        for (size_t j = 0; j < MAX_PVC_ITERATION; ++j) {
            logOT.io = io_.at(get_index(j));
            logOT.reseed(&seeds_B_[j]);
            bool bb = ((chosen_index_ - j) == 0);
            logOT.recv(&seeds_A_[j], &bb, 1);
            tx_sd_ot_[j].resize(logOT.log_length());
            logOT.get_log(tx_sd_ot_[j].data(), tx_sd_ot_[j].size());
            logOT.clear();
        }
    }

    void send_seeds_hash() const {
        /* send hash of seedB */
        hash_t digest;
        for (const auto &seed : seeds_B_) {
            hsher.hash_once(digest.data(), &seed, sizeof(block));
            aux_io_->send_data(digest.data(), sizeof(hash_t));
        }
        aux_io_->flush();
    }

    bool verify_trans_sign(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        auto io = io_[get_index(j)];
        io->recv_data(&(tx_sign_[j]->sig_len), sizeof(int32_t));
        io->recv_data(tx_sign_[j]->payload, tx_sign_[j]->sig_len);

        hash_t h;
        int32_t tx_len;
        io->recv_data(&tx_len, sizeof(int32_t));
        rev_ot_tx_[j].resize(tx_len);
        io->recv_data(rev_ot_tx_[j].data(), tx_len);
        hsher.hash_once((char *)h.data(), rev_ot_tx_[j].data(), tx_len);
        PVCJudge judge;
        return judge.verify_sign(j, rev_com_[j], h, seeds_B_[j],
                                 tx_sd_ot_[j], tx_sign_[j]->payload,
                                 tx_sign_[j]->sig_len, ver_key_);
    }

    void receive_ver_key() {
        int32_t len;
        io_[0]->recv_data(&len, sizeof(len));
        if (len < 0 || len > ECDSA_VK_BYTES) {
            std::cerr << "Received invalid verification key" << std::endl;
            exit(1);
        } else {
            uint8_t buf[ECDSA_VK_BYTES];
            io_[0]->recv_data(buf, len);
            ecdsa_deserialize_ver_key(ver_key_, buf, len);
        }
    }

    void send_witness() const {
        int32_t j = chosen_index_;
        io_[0]->send_data(&j, sizeof(int32_t));
        for (int i = 0; i < MAX_PVC_ITERATION; ++i) {
            io_[0]->send_data(&seeds_A_[i], sizeof(block));
        }
        io_[0]->flush();
    }

    bool recv_and_check_sign_trans(int *invalid) {
        receive_ver_key(); /* this step might be replaced by PKI */
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            if (!verify_trans_sign(j)) {
                if (invalid) *invalid = j;
                return false;
            }
        }
        return true;
    }

    bool check_ot_trans(int *invalid) {
        hash_t dig;
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            if (j == chosen_index_) continue;
            hsher.hash_once((char *) dig.data(), 
                            rev_ot_tx_[j].data(), 
                            rev_ot_tx_[j].size());
            if (dig != sim_ot_tx_dgst_[j]) {
                *invalid = j;
                std::cerr << "Invalid ot trans" << std::endl;
                return false;
            }
        }
        return true;
    }

    bool recv_and_check_circuit_commits() {
        int valid = -1;
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            aux_io_->recv_data(rev_com_[j], sizeof(Com));
            if (j != chosen_index_ &&
                0 != std::memcmp(sim_com_[j], rev_com_[j], sizeof(Com))) {
                valid = j;
            }
        }
        return valid == -1;
    }

    template <typename RT>
    void simulate_gc_commit(typename TPC<RT>::T const& circ) {
        PVCJudge judge;
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            if (j == chosen_index_) continue;
            judge.simulate_gc_commit<RT>(sim_com_[j], seeds_A_[j], circ);
        }
    }

    template <typename RT>
    void run_real_ot(typename TPC<RT>::T const& circ, const void *bob_input) {
#pragma omp parallel for num_threads(2)
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            setup_ot(j);
            circ(nullptr, bob_input, TPCF_OT_ONLY);
        }
    }

    template <typename RT>
    bool run_real_gc(typename TPC<RT>::T const& circ, const void *bob_input) {
        /* run real GC with real input */
        setup_real_gc(chosen_index_);
        circ(nullptr, bob_input, TPCF_REAL_GC);
        if (!check_decomit()) {
            std::cout << "Abort: invalid decomitment.\n";
            return false;
        }
        bool ok = false;
        RT rt = decode_output_wires<RT>(&ok);
#ifndef NDEBUG
        if (ok)
            std::cout << "ans = " << rt << std::endl;
        else
            std::cout << "decoding failed" << std::endl;
#endif
        return ok;
    }

    template <typename RT>
    void ot_in_the_head(typename TPC<RT>::T const& circ) {
        PVCJudge judge;
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            if (j == chosen_index_) continue;
            judge.ot_in_the_head<RT>(sim_ot_tx_dgst_[j],
                                     seeds_A_[j], seeds_B_[j], circ);
        }
    }

    bool check_decomit() {
        hash_t dig;
        hash_gc_io_->get_digest((char *)dig.data());
        Decom decom;
        hash_t plyld;
        io_[get_index(chosen_index_)]->recv_data(&decom, sizeof(block));
        io_[get_index(chosen_index_)]->recv_data(plyld.data(), sizeof(hash_t));
        if (dig != plyld) {
            std::cout << "----- invalid gc commit ------\n" << std::endl;
            for (auto c : dig) { printf("%02x", c); printf("\n"); }
            for (auto c : plyld) { printf("%02x", c); printf("\n"); }
            return false;
        }
        Commitment commiter;
        return commiter.open(decom, rev_com_[chosen_index_],
                             plyld.data(), Hash::DIGEST_SIZE);
    }

    template <class ReT>
    ReT decode_output_wires(bool *ok) {
        std::vector<std::thread> workers;
        const int n_workers = 8;
        const size_t n_jobs = output_labels_.size();
        const size_t batch = std::max(1UL, (n_jobs + n_workers - 1) / n_workers);
        hsh_ow_.resize(n_jobs);
        for (int i = 0; i < n_workers; ++i) {
            size_t from = i * batch;
            size_t to = std::min(n_jobs, from + batch);
            workers.emplace_back([this](size_t id, size_t end) {
                block l;
                int64_t *d = (int64_t *) &l;
                while (id != end) {
                    l = label_prp.H(output_labels_[id], 2 * id);
                    hsh_ow_[id++] = *d;
                }
            }, from, to);
        }

        int32_t cnt_ow = -1;
        io_[get_index(chosen_index_)]->recv_data(&cnt_ow, sizeof(int32_t));
        assert(cnt_ow >= 0);
        int64_t hsh;
        rev_hsh_ow_.reserve(cnt_ow);
        for (int i = 0; i < cnt_ow; ++i) {
            io_[get_index(chosen_index_)]->recv_data(&hsh, sizeof(int64_t));
            rev_hsh_ow_.push_back(hsh);
        }

        for (auto &w : workers) w.join();
        size_t nr_labels = hsh_ow_.size();
        if (nr_labels * 2 != rev_hsh_ow_.size()) {
            if (ok) *ok = false;
            std::cerr << "Need " << nr_labels * 2 << " wires, but got "
                      << rev_hsh_ow_.size() << std::endl;
            return ReT{};
        }
        std::vector<bool> bits; 
        bits.reserve(nr_labels);
        for (size_t i = 0; i < nr_labels; ++i) {
            int64_t  d = hsh_ow_[i];
#ifdef DEBUG
            if (d == rev_hsh_ow_[i * 2]) {
                bits.push_back(false);
            } else if (d == rev_hsh_ow_[i * 2 + 1]) {
                bits.push_back(true);
            } else {
                std::cerr << "Semantic wrong " << i << "\n";
                if (ok) *ok = false;
                return ReT{};
            }
#else
            if (d == rev_hsh_ow_[i * 2]) 
                bits.push_back(false);
            else 
                bits.push_back(true);
#endif
        }
        if (ok) *ok = true;
        return nr_labels < 2048 ? Revealer<ReT>::reveal(bits) : "too long";
    }

    void do_create_cheated_cert(std::ostream& out, int32_t j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        hsher.reset();
        uint8_t buf0[128];
        int32_t key_len = ecdsa_serialize_ver_key(buf0, 128, ver_key_);
        /* Alice's pk */
        out.write((const char *)&key_len, sizeof(int32_t));
        out.write((const char *)buf0, key_len);
        /* index */
        out.write((const char *)&j, sizeof(int32_t));
        /* ecdsa signature */
        out.write((const char *)&tx_sign_[j]->sig_len, sizeof(int32_t));
        out.write((const char *)&tx_sign_[j]->payload[0], tx_sign_[j]->sig_len);
        /* GC commitment */
        out.write(rev_com_[j], sizeof(Com));
        /* hashed OT transcript */
        int32_t len = rev_ot_tx_[j].size();
        out.write((const char *) &len, sizeof(int32_t));
        out.write((const char *) rev_ot_tx_[j].data(), len);
        /* seedB */
        out.write((const char *)&seeds_B_[j], sizeof(block));
        /* seed OT transcript */
        len = tx_sd_ot_[j].size();
        out.write((const char *) &len, sizeof(int32_t));
        out.write((const char *) tx_sd_ot_[j].data(), len);
    }

    template <class RT>
    void judge_cert(typename TPC<RT>::T const& circ) {
        PVCJudge judge;
        printf("Judge: %d\n", judge.judge<RT>("cheated.cert", circ));
    }

    void create_cheated_cert(int32_t j) {
        std::ofstream fout("cheated.cert");
        if (fout.is_open()) {
            do_create_cheated_cert(fout, j);
            fout.close();
        } else {
            do_create_cheated_cert(std::cout, j);
        }
    }
};
}
