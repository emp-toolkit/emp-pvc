#pragma once

#include <emp-tool/utils/hash.h>
#include <array>
#include <vector>
#include <iostream>
#include <cstring>

namespace emp {
using hash_t = std::array<uint8_t, Hash::DIGEST_SIZE>;

struct HashArray {
public:
    HashArray() {}

    ~HashArray() {}

    void reserve(size_t n) {
        arr_.reserve(n);
    }

    void put(hash_t const& h) {
        arr_.push_back(h);
        hsh.put(h.data(), sizeof(hash_t));
    }

    void digest(hash_t &dig) {
        if (arr_.empty())
            std::cerr << "Digest on empty string" << std::endl;
        digest(dig.data());
    }

    void digest(uint8_t *dig) {
        if (arr_.empty())
            std::cerr << "Digest on empty string" << std::endl;
        hsh.digest((char *)dig);
    }

    bool equal(HashArray const& oth) const {
        if (count() != oth.count())
            return false;
        for (size_t i = 0; i < arr_.size(); ++i) {
            if (std::memcmp(get(i).data(), 
                            oth.get(i).data(), 
                            sizeof(hash_t))) {
                return false;
            }
        }
        return true;
    }

    size_t count() const { return arr_.size(); }

    const hash_t& get(size_t i) const { return arr_.at(i); }

    void reset() {
        hsh.reset();
        std::vector<hash_t>().swap(arr_);
    }

private:
    Hash hsh;
    std::vector<hash_t> arr_;
};

}

