#pragma once
#include <emp-tool/io/io_channel.h>
#include <emp-tool/io/net_io_channel.h>
#include <emp-tool/utils/hash.h>
#include <cstring>
namespace emp {
class FreeGCHashIO : public IOChannel<FreeGCHashIO> {
    char internal[Hash::DIGEST_SIZE];
    NetIO *io = nullptr;

    void hash_gc(const block* data) {
        Hash hasher;
        hasher.put_block(data, 2);
        char digest[Hash::DIGEST_SIZE];
        hasher.digest(digest);
        for (size_t i = 0; i < Hash::DIGEST_SIZE; ++i)
          internal[i] ^= digest[i];
    }
public:
    explicit FreeGCHashIO(NetIO *io_ = nullptr) 
        : io(io_)
    { std::memset(internal, 0u, Hash::DIGEST_SIZE); }

    void send_data(const void * data, int len) {
        assert(len == 2 * sizeof(block));
        hash_gc((const block *) data);
        if (io) io->send_data(data, len);
    }

    void send_block(const block *blk, int len) {
        assert(len == 2);
        send_data(blk, sizeof(block) * 2);
    }

	  void recv_data(void * data, int len) {
        if (io) {
            io->recv_data(data, len);
            assert(len == 2 * sizeof(block));
            hash_gc((const block *) data);
        }
	  }

    void get_digest(char * dgst) {
        if (!dgst)
            return;
        std::memcpy(dgst, internal, Hash::DIGEST_SIZE);
        std::memset(internal, 0u, Hash::DIGEST_SIZE);
	  }
};
}
