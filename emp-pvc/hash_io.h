#pragma once

#include <emp-tool/io/io_channel.h>
#include <emp-tool/io/mem_io_channel.h>
#include <emp-tool/io/net_io_channel.h>
#include <emp-tool/utils/hash.h>
#include "emp-pvc/pipe_io.h"
#include "emp-pvc/hash_array.h"

#include <iostream>
namespace emp {

class BaseHashedIO {
private:
    Hash hsh;

public:
    BaseHashedIO() {}

    ~BaseHashedIO() {}

    void digest(uint8_t *dig) {
        hsh.digest((char *)dig);
        reset();
    }

    void reset() {
        hsh.reset();
    }

protected:
    void put(const void *data, int len) {
        hsh.put(data, len);
    }
};

#define CREATE_HASH_IO(NAME, BaseIO) \
class NAME : public BaseHashedIO, \
             public IOChannel<NAME> { \
private: \
    using T = BaseIO; \
    State state_ = State::INIT; \
    void transit(State new_state) { \
        if (state_ == State::INIT) { \
            state_ = new_state; \
            return; \
        } \
        if (state_ != new_state) { \
            hash_t dig; \
            digest(dig.data()); \
            hsh_array.put(dig); \
            state_ = new_state; \
        } \
    } \
public: \
    T *io; \
    HashArray hsh_array; \
    explicit NAME(T *io_) : io(io_) { \
    } \
    int count() const { \
        return hsh_array.count() + (state_ != State::INIT); \
    } \
    void finalize() { \
        if (state_ != State::INIT) { \
            transit(State::INIT); \
        } \
    } \
    void send_block(const block *data, int nblock) { \
        transit(State::SENT); \
        IOChannel<NAME>::send_block(data, nblock); \
    } \
    void recv_block(block* data, int nblock) { \
        transit(State::RECV); \
        IOChannel<NAME>::recv_block(data, nblock); \
    } \
    void send_eb(const eb_t *eb, size_t num) { \
        transit(State::SENT); \
        IOChannel<NAME>::send_eb(eb, num); \
    } \
    void recv_eb(eb_t* eb, size_t num) { \
        transit(State::RECV); \
        IOChannel<NAME>::recv_eb(eb, num); \
    } \
    void send_bn(const bn_t *bn, size_t num) { \
        transit(State::SENT); \
        IOChannel<NAME>::send_bn(bn, num); \
    } \
    void recv_bn(bn_t* bn, size_t num) { \
        transit(State::RECV); \
        IOChannel<NAME>::recv_bn(bn, num); \
    } \
    void send_data(const void *data, int len) { \
        transit(State::SENT); \
        if (io) \
            io->send_data(data, len); \
        BaseHashedIO::put(data, len); \
    } \
    void recv_data(void *data, int len) { \
        if (io) { \
            transit(State::RECV); \
            io->recv_data(data, len); \
            BaseHashedIO::put(data, len); \
        } \
    } \
    void flush() { \
        if (io) io->flush(); \
    } \
    ~NAME() {} \
}; 

CREATE_HASH_IO(HashedIO, NetIO);

CREATE_HASH_IO(PHashedIO, PipeIO);
} 
