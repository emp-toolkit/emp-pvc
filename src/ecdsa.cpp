#include "emp-pvc/ecdsa.h"

#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <cstring>

static const int ecdsa_group = NID_X9_62_prime256v1;

void ecdsa_key_gen(sig_key_t sk)
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(ecdsa_group);
    sk->key = EC_KEY_new();
    EC_KEY_set_group(sk->key, group);
    EC_KEY_generate_key(sk->key);
    EC_GROUP_free(group);
}

void ecdsa_release(sig_key_t sk)
{
    EC_KEY_free(sk->key);
}

void ecdsa_release(ver_key_t vk)
{
    EC_KEY_free(vk->key);
}

void ecdsa_get_ver_key(ver_key_t vk, const sig_key_t sk)
{
    vk->key = EC_KEY_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(ecdsa_group);
    EC_KEY_set_group(vk->key, group);
    EC_KEY_set_public_key(vk->key, EC_KEY_get0_public_key(sk->key));
    EC_GROUP_free(group);
}

int ecdsa_serialize_ver_key(
    uint8_t *buf, 
    const int cap, 
    const ver_key_t vk)
{
    if (!vk->key || cap < ECDSA_VK_BYTES)
        return 0;

    int len = i2o_ECPublicKey(vk->key, &buf);
    return len > 0 ? len : 0;
}

bool ecdsa_deserialize_ver_key(
    ver_key_t vk,
    const uint8_t *buf,
    const int len)
{
    vk->key = EC_KEY_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(ecdsa_group);
    EC_KEY_set_group(vk->key, group);
    vk->key = o2i_ECPublicKey(&(vk->key), &buf, len);
    EC_GROUP_free(group);
    return vk->key != nullptr;
}

int ecdsa_sign(
    uint8_t *sig, 
    const int cap,
    const uint8_t *msg, 
    const int msglen, 
    const sig_key_t sk)
{
    if (cap < ECDSA_SIGN_BYTES)
        return 0;
    unsigned char hash[32];
    if (!SHA256(msg, msglen, hash))
        return 0;
    ECDSA_SIG* signt = ECDSA_do_sign(hash, 32, sk->key);
    if (!signt)
        return 0;
    int pos = i2d_ECDSA_SIG(signt, &sig);
    ECDSA_SIG_free(signt);
    return pos;
}

bool ecdsa_verify(
    const uint8_t *sig, 
    const int sig_len,
    const uint8_t *msg, 
    const int msglen, 
    const ver_key_t vk)
{
    unsigned char hash[32];
    if (!SHA256(msg, msglen, hash))
        return 0;
    return ecdsa_verify_hash(sig, sig_len, hash, 32, vk);
}

bool ecdsa_verify_hash(
    const uint8_t *sig, 
    const int sig_len,
    const uint8_t *hsh, 
    const int hsh_len, 
    const ver_key_t vk)
{
    ECDSA_SIG *signt = nullptr;
    d2i_ECDSA_SIG(&signt, &sig, sig_len);
    if (!signt)
        return false;
    bool ok = (ECDSA_do_verify(hsh, hsh_len, signt, vk->key) == 1);
    ECDSA_SIG_free(signt);
    return ok;
}
