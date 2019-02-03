#pragma once
#include <cstdint>
#include <openssl/ecdsa.h>
constexpr int ECDSA_SIGN_BYTES = 72; // secp256r1 curve
constexpr int ECDSA_VK_BYTES = 65;
struct sig_key_st {
    EC_KEY *key;
};

struct ver_key_st {
    EC_KEY *key;
};

using sig_key_t = sig_key_st[1];
using ver_key_t = ver_key_st[1];

void ecdsa_key_gen(sig_key_t sk);

void ecdsa_release(sig_key_t);

void ecdsa_release(ver_key_t);

void ecdsa_get_ver_key(ver_key_t vk, const sig_key_t sk);

int ecdsa_serialize_ver_key(
    uint8_t *buf,
    const int cap,
    const ver_key_t vk);

bool ecdsa_deserialize_ver_key(
    ver_key_t vk,
    const uint8_t *buf,
    const int len);

int ecdsa_sign(
    uint8_t *sig, 
    const int cap, 
    const uint8_t *msg, 
    const int msg_len,
    const sig_key_t sk);

bool ecdsa_verify(
    const uint8_t *sig,
    const int sig_len,
    const uint8_t *msg,
    const int msg_len,
    const ver_key_t vk);

bool ecdsa_verify_hash(
    const uint8_t *sig,
    const int sig_len,
    const uint8_t *hsh,
    const int hsh_len,
    const ver_key_t vk);
