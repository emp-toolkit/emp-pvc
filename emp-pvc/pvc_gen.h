#pragma once
#include "emp-pvc/judge.h"
#include "emp-pvc/common.h"
#include "emp-pvc/logged-ot.h"
#include "emp-pvc/hash_array.h"
#include "emp-pvc/internal_gen.h"
#include "emp-pvc/gc_commit_gen.h"
#include "emp-pvc/gc_hash_io.h"
#include "emp-pvc/ecdsa.h"

#include <deque>
#include <memory>
#ifdef DEBUG
static const char *_debug_fix_key = "dfadf34562c12353qfdasf";
#endif

namespace emp {
extern thread_local int itr;
template <typename IO>
class PVCGen: public ProtocolExecution {
private:
    using garbler_t = HalfGateGen<IO>;
    using generator_t = InternalGen<IO, garbler_t, /*HashOT*/true>;
    using bytes_t = std::vector<uint8_t>;

    inline int get_index(int j) const { return std::min(j, num_io_ - 1); }
    const int num_io_;
    std::vector<IO *> io_;
    IO *aux_io_ = nullptr;
    std::vector<garbler_t *> gc_;
    std::vector<generator_t *> gen_;

    sig_key_t sig_key_;
public:
    explicit PVCGen(std::vector<IO *> iov, IO *aio)
        : ProtocolExecution(ALICE),
          num_io_(iov.size()),
          io_(iov),
          aux_io_(aio)
    {
        assert(num_io_ > 0);
        gc_.resize(num_io_, nullptr);
        gen_.resize(num_io_, nullptr);
        ecdsa_key_gen(sig_key_);
    }

    ~PVCGen() {
        std::memset(sig_key_, 0x0, sizeof(sig_key_));
        std::memset(seeds_A_, 0x0, sizeof(seeds_A_));
        std::memset(witness_, 0x0, sizeof(witness_));
        for (int i = 0; i < num_io_; ++i) {
             delete gc_[i];
             delete gen_[i];
        }
    }

    template <typename RT>
    bool run(typename TPC<RT>::T const& circ, const void *alice_input) {
        rand_seeds();
        /* concurrently run small tasks along with realOT */
        std::thread small_tasks([this, &circ] {
            pvc_create_commitment<RT>(circ);
            send_circuit_commits();
            recv_seeds_hash();
        });

        ot_on_seeds();
        run_real_ot<RT>(circ, alice_input);
        small_tasks.join();
        /* wait commitments to be created */
        send_sign_transcript(); 
        bob_choice_ = check_witness();

        if (bob_choice_ >= 0) {
            return run_real_gc<RT>(circ, alice_input);
        } else {
            std::cout << "invalid witness\n";
            return false;
        }
    }

    void feed(block *label, int party, const bool *b, int len) override
    {
        gen_[get_index(itr)]->feed(label, party, b, len);
    }

    void reveal(bool *b, int party, const block *label, int len) override
    {
        assert(state == State::GC);
        assert(itr == bob_choice_);
        if (party == BOB) {
            int idx = get_index(bob_choice_);
            block l;
            uint64_t *low_half = (uint64_t *) &l;
            for (int i = 0; i < len; ++i) {
                // 0-wire
                l = label_prp.H(*label, label_id * 2);
                hsh_outwires_[bob_choice_].push_back(*low_half);
                // 1-wire
                l = label_prp.H(xorBlocks(*label++, gc_[idx]->delta),
                                label_id * 2 + 1);
                ++label_id; 
                hsh_outwires_[bob_choice_].push_back(*low_half);
            }
        }
    }
private:
    Hash      hsher;
    uint64_t  label_id = 0;
    PRP       label_prp; /* use prp as a hash function for Bob's ouput labels */
    block     seeds_A_[MAX_PVC_ITERATION];
    block     witness_[MAX_PVC_ITERATION];
    bytes_t   tx_sd_ot_[MAX_PVC_ITERATION];       /* transcript of seed ot */
    bytes_t   tx_ot_[MAX_PVC_ITERATION];          /* transcript of ot, hashed of each round */
    hash_t    digest_seeds_B_[MAX_PVC_ITERATION]; /* Bob's seeds which are received from Bob */
    hash_t    hsh_gc_[MAX_PVC_ITERATION];         /* Hash of GC */
    std::vector<int64_t> hsh_outwires_[MAX_PVC_ITERATION];
    Com       cir_com_[MAX_PVC_ITERATION];        /* circuit commiment */
    Decom     cir_decom_[MAX_PVC_ITERATION];      /* circuit decommitment */
    int       bob_choice_ = -1;                   /* Bob's chosen index */
    State     state = State::INIT;

    template <typename RT>
    void pvc_create_commitment(typename TPC<RT>::T const& circ) {
        PVCJudge judge;
#pragma omp parallel for 
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            judge.simulate_gc_commit<RT>(cir_com_[j], cir_decom_[j],
                                         &hsh_gc_[j], seeds_A_[j], circ);
        }
    }

    void send_circuit_commits() const {
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            aux_io_->send_data(cir_com_[j], sizeof(Com));
        }
        aux_io_->flush();
    }

    void send_sign_transcript() {
        send_ver_key();
        for (int j = 0; j < MAX_PVC_ITERATION; ++j)
            send_sign_trans(j);
    }

    template <class RT>
    void run_real_ot(typename TPC<RT>::T const& circ, const void *alice_input) {
#pragma omp parallel for num_threads(2)
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            setup_ot(j);
            circ(alice_input, nullptr, TPCF_OT_ONLY);
            tx_ot_[j] = gen_[get_index(j)]->getOTDigest();
            io_[get_index(j)]->flush();
        }
    }

    template <class RT>
    bool run_real_gc(typename TPC<RT>::T const& circ, 
                     const void *alice_input) {
        setup_real_gc(bob_choice_);
        circ(alice_input, nullptr, TPCF_REAL_GC);
        send_decomit(bob_choice_);
        send_outwires_hsh(bob_choice_);
        io_[bob_choice_]->flush();
        return true;
    }

    /*
     * transcript := (index || commit || GC OT transcript hash || seed_B hash || Seed OTs transcript hash)
     * send 1. sign of transcript, 2. commit, 3., ot transcript
     * */
    void send_sign_trans(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        uint8_t buf[1 + sizeof(Com) + sizeof(hash_t) * 3];
        /* index */
        buf[0] = (uint8_t)j;
        uint8_t *ptr = &(buf[1]);
        /* commit */
        std::memcpy(ptr, cir_com_[j], sizeof(Com));
        ptr += sizeof(Com);
        /* OT transcript, but we sign its hash */
        hsher.hash_once((char *)ptr, tx_ot_[j].data(), tx_ot_[j].size());
        ptr += sizeof(hash_t);
        /* hash of seedB */
        std::memcpy(ptr, digest_seeds_B_[j].data(), sizeof(hash_t));
        ptr += sizeof(hash_t);
        /* seedOT transcript, also sign its hash */
        hsher.hash_once((char *)ptr, tx_sd_ot_[j].data(), tx_sd_ot_[j].size());
        ptr += sizeof(hash_t);

        int msg_len = std::distance(&buf[0], ptr);
	uint8_t sig[ECDSA_SIGN_BYTES];
        int32_t len = ecdsa_sign(sig, sizeof(sig), buf, msg_len, sig_key_);
        if (len == 0) {
            std::cerr << "ecdsa sign fails" << std::endl;
            exit(1);
        }
        /* send sign of transcript */
        auto io = io_[get_index(j)];
        io->send_data(&len, sizeof(int32_t));
        io->send_data(sig, len);
        /* follows by the OT transcript */
        len = tx_ot_[j].size();
        io->send_data(&len, sizeof(int32_t));
        io->send_data(tx_ot_[j].data(), len);
        io->flush();
    }

    void send_ver_key() const {
        ver_key_t vk;
        ecdsa_get_ver_key(vk, sig_key_);
        uint8_t buf[ECDSA_VK_BYTES];
        int32_t len = ecdsa_serialize_ver_key(buf, sizeof(buf), vk);
        auto io = io_[0];
        io->send_data(&len, sizeof(len));
        io->send_data(buf, len);
        io->flush();
    }

    void rand_seeds() {
        PRG prg;//(fix_key);
        prg.random_block(seeds_A_, MAX_PVC_ITERATION);
        prg.random_block(witness_, MAX_PVC_ITERATION);
    }
    /*
     * Run MAX_PVC_ITERATION 1-of-2 OT on seeds.
     */
    void ot_on_seeds() {
        block tmp;
        LoggedOTCO<IO> logOT(nullptr);
        PRG prg;
        for (int j = 0; j < MAX_PVC_ITERATION; ++j) {
            logOT.io = io_.at(get_index(j));
            prg.random_block(&tmp);
            logOT.reseed(&tmp);
            logOT.send(&seeds_A_[j], &witness_[j], 1);
            tx_sd_ot_[j].resize(logOT.log_length());
            logOT.get_log(tx_sd_ot_[j].data(), tx_sd_ot_[j].size());
            io_[get_index(j)]->flush();
            logOT.clear();
        }
    }

    void recv_seeds_hash() {
        /* receive hash of seed B. */
        for (auto &dig : digest_seeds_B_)
            aux_io_->recv_data(dig.data(), sizeof(hash_t));
    }
    /*
     * Receive witness from Bob, then check the witness.
     * @return Bob's choice if the witness is valid, otherwise return -1.
     */
    int check_witness() const {
        bool ok = true;
        int32_t j = -1;
        io_[0]->recv_data(&j, sizeof(int32_t));
        if (j < 0 || j >= MAX_PVC_ITERATION)
            ok = false;

        block wt;
        for (int i = 0; i < MAX_PVC_ITERATION; ++i) {
            io_[0]->recv_data(&wt, sizeof(block));
            if (i != j)
                ok &= cmpBlock(&wt, &seeds_A_[i], 1);
            else
                ok &= cmpBlock(&wt, &witness_[i], 1);
        }

        return ok ? j : -1;
    }

    void send_decomit(int j) const {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        io_[get_index(j)]->send_data(cir_decom_[j], sizeof(block));
        io_[get_index(j)]->send_data(hsh_gc_[j].data(), sizeof(hash_t));
    }

    void send_outwires_hsh(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        int32_t cnt_ow = hsh_outwires_[j].size();
        io_.at(get_index(j))->send_data(&cnt_ow, sizeof(int32_t));
        const auto& hw = hsh_outwires_[j];
        for (int i = 0; i < cnt_ow; ++i) {
            io_[get_index(j)]->send_data(&hw[i], sizeof(int64_t)); // only send 64-bits
        }
    }

    void setup_exec(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        itr = j;
        state = State::INIT;
        const int idx = get_index(j);
        if (gc_[idx])  delete gc_[idx]; 
        if (gen_[idx]) delete gen_[idx];
        gc_[idx] = new garbler_t(io_[idx]);
        gen_[idx] = new generator_t(io_[idx], gc_[idx], &seeds_A_[j]);
        CircuitExecution::circ_exec = gc_[idx];
        ProtocolExecution::prot_exec = this;
    }

    void setup_real_gc(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        setup_exec(j);
        state = State::GC;
        gen_[get_index(j)]->state = state;
    }

    void setup_ot(int j) {
        assert(j >= 0 && j < MAX_PVC_ITERATION);
        setup_exec(j);
        state = State::OT;
        gen_[get_index(j)]->state = state;
    }
};
}
