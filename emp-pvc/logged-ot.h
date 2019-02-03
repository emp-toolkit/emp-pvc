#pragma once
#include <emp-ot/ot.h>
#include <emp-ot/table.h>
#include <emp-tool/io/mem_io_channel.h>

#include <memory>
#include <cstring>
#include <atomic>

namespace emp {

template <class IO>
class LoggedOTCO : public OT<LoggedOTCO<IO>> {
private:
    MemIO alice_logger_;
    MemIO bob_logger_;
public:
    int cnt;
	  eb_t g;
	  bn_t q;
	  PRG prg;
	  IO* io;
    eb_t tbl[RELIC_EB_TABLE_MAX];

    explicit LoggedOTCO(IO *io_)
        : io(io_)
    {
        this->io = io;
        eb_curve_get_gen(g);
        eb_curve_get_ord(q);
        MemIO mio;
        char *tmp = mio.buffer;
        mio.buffer = (char *) eb_curve_get_tab_data;
        mio.size = 15400 * 8;
        mio.recv_eb(tbl, RELIC_EB_TABLE_MAX);
        eb_new(C);
        mio.buffer = tmp;
    }
    /*
     * Copy from emp::OTCO.
     */
    void send_impl(const block* data0, const block* data1, int length) {
        assert(length == 1);
        bn_t a;
        eb_t A, B;
        eb_newl(A, B);
        bn_newl(a);

        prg.random_bn(&a, 1);
        eb_mul_fix_norm(A, tbl, a);
        io->send_eb(&A, 1);
        io->recv_eb(&B, 1);

        alice_logger_.send_data(&length, sizeof(int32_t));
        alice_logger_.send_eb(&A, 1);
        bob_logger_.send_eb(&B, 1);

        eb_mul_norm(B, B, a);
        bn_sqr(a, a);
        bn_mod(a, a, q);
        eb_mul_fix_norm(A, tbl, a);
        eb_sub_norm(A, B, A);

        block res[2];
        res[0] = xorBlocks(KDF(B), *data0);
        res[1] = xorBlocks(KDF(A), *data1);

        io->send_data(res, 2*sizeof(block));
        alice_logger_.send_data(res, 2*sizeof(block));

        eb_freel(A, B);
        bn_freel(a);
    }

    void recv_impl(block* data, const bool* b, int length) {
        assert(length == 1);
        bn_t bb;
        eb_t A, B;
        eb_newl(A, B);
        bn_newl(bb);

        prg.random_bn(bb, 1);
        eb_mul_fix_norm(B, tbl, bb);
        io->recv_eb(&A, 1);
        if (*b) eb_add_norm(B, A, B);
        io->send_eb(&B, 1);

        alice_logger_.send_data(&length, sizeof(int32_t));
        alice_logger_.send_eb(&A, 1);

        eb_mul_norm(A, A, bb);
        *data = KDF(A);

        block res[2];
        io->recv_data(res, 2*sizeof(block));
        *data = xorBlocks(*data, res[*b ? 1u : 0u]);

        bob_logger_.send_eb(&B, 1);
        alice_logger_.send_data(res, 2 * sizeof(block));
        eb_freel(A, B);
        bn_freel(bb);
    }

    void reseed(block *seed) {
        if (seed)
            prg.reseed(seed);
    }

    int log_length() const {
        //return static_cast<int>(alice_logger_.size + bob_logger_.size);
        return static_cast<int>(alice_logger_.size);
    }

    void clear() {
        alice_logger_.clear();
        bob_logger_.clear();
    }
    // Format: N(4 bytes)|N eb|2N blocks|N eb
    //                   <----alice----><-bob->
    int get_log(uint8_t *out, int cap) {
        if (!out || cap <= 0) return 0;
        int len = std::min(cap, log_length());
        std::memcpy(out, alice_logger_.buffer, alice_logger_.size);
        //std::memcpy(out + alice_logger_.size, bob_logger_.buffer, bob_logger_.size);
        return len;
    }
};
} // namespace emp
