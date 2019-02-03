#include "emp-pvc/emp-pvc.h"
#include "emp-pvc/utils.h"
#include "emp-pvc/common.h"
#include <thread>
#include <string>
#include <sstream>
#include <map>
#include <cassert>
using namespace emp;
const std::string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
int g_party = -1;
long ALICE_LEN = -1;
long BOB_LEN = -1;
long GATE = 1024;
long OUT_LEN = 128;
int PORT = 12345;
using Rt = std::string;
using runner_t = typename TPC<Rt>::T;

Rt run_bench(const void *al, const void *bb, int flag)
{
    long alice_len = std::max(128L, ALICE_LEN);
    long bob_len = std::max(128L, BOB_LEN);
    Integer a(alice_len, 0, ALICE);
    Integer b(bob_len, 0, BOB);
    if (flag & TPCF_OT_ONLY)
        return "";
    Bit c;
    for (long i = 0; i < GATE; ++i)
        c = a[0] & b[0];
    for (long i = 0; i < OUT_LEN; ++i)
        c.reveal<bool>(BOB);  
    return "";
}

Rt run_mult_circut(const void *al, const void *bb, int flag)
{
    long alice_len = std::max(2048L, ALICE_LEN);
    long bob_len = std::max(2048L, BOB_LEN);
    Integer a(alice_len, 5L, ALICE);
    Integer b(bob_len, 7L, BOB);
    if (flag & TPCF_OT_ONLY)
        return "";
    Integer c = a * b;
    c.reveal<string>(BOB);
    return "";
}

Rt run_hamming_distance(const void *al, const void *bb, int flag)
{
    long alice_len = std::max(1048576L, ALICE_LEN);
    long bob_len = std::max(1048576L, BOB_LEN);
    Integer a(alice_len, 5L, ALICE);
    Integer b(bob_len, 7L, BOB);
    if (flag & TPCF_OT_ONLY)
        return "";
    Integer c = (a ^ b).hamming_weight();
    c.reveal<string>(BOB);
    return "";
}

std::string aes_cfile = circuit_file_location + "/AES-non-expanded.txt";
CircuitFile aes_cf(aes_cfile.c_str());
Rt run_aes_circut(const void *al, const void *bb, int flag)
{
    long alice_len = std::max(128L, ALICE_LEN);
    long bob_len = std::max(128L, BOB_LEN);
    Bit *a = new Bit[alice_len];
    Bit *b = new Bit[bob_len];
    bool ab[alice_len], ba[bob_len];
    for (long i = 0; i < alice_len; ++i) ab[i] = true;
    for (long i = 0; i < bob_len; ++i) ba[i] = true;
    init(a, ab, alice_len, ALICE); // msg
    init(b, ba, bob_len, BOB);

    Integer c(128, 0, PUBLIC);
    if (flag & TPCF_OT_ONLY)
        return "";
    // simulate gc, it might be threading, so we copy the gc file.
    CircuitFile cf{aes_cf};
    cf.compute((block *)c.bits, (block *)a, (block *)b);
    for (int i = 0; i < 128; ++i)
        c[i].reveal<bool>(BOB);
    delete []a;
    delete []b;
    return "";
}

std::string sha1_cfile = circuit_file_location + "/sha-1.txt";
CircuitFile sha1_cf(sha1_cfile.c_str());
Rt run_sha1_circut(const void *, const void *, int flag)
{
    long alice_len = std::max(512L, ALICE_LEN);
    long bob_len = std::max(512L, BOB_LEN);
    bool alice_bits[alice_len];
    std::memset(alice_bits, false, alice_len);
    bool bob_bits[bob_len];
    std::memset(bob_bits, true, bob_len);

    Bit *alice = new Bit[alice_len];
    Bit *bob = new Bit[bob_len];

    init(alice, alice_bits, alice_len, ALICE);
    init(bob, bob_bits, bob_len, BOB);
    Integer c(160, true, PUBLIC);

    if (flag & TPCF_OT_ONLY)
        return "";
    for (int i = 0; i < 512; ++i)
        alice[i] = alice[i] ^ bob[i];
    if (flag & TPCF_REAL_GC) {
        sha1_cf.compute((block *)c.bits, (block *)alice, nullptr);
    } else { // simulate gc, it might be threading, so we copy the gc file.
        CircuitFile cf{sha1_cf};
        cf.compute((block *)c.bits, (block *)alice, nullptr);
    }
    for (size_t i = 0; i < 160; ++i)
        c[i].reveal<bool>(BOB);
    return "";
}

std::string sha256_cfile = circuit_file_location + "/sha-256.txt";
CircuitFile sha256_cf(sha256_cfile.c_str());
Rt run_sha256_circut(const void *, const void *, int flag)
{
    long alice_len = std::max(512L, ALICE_LEN);
    long bob_len = std::max(512L, BOB_LEN);
    bool alice_bits[alice_len];
    std::memset(alice_bits, false, alice_len);
    bool bob_bits[bob_len];
    std::memset(bob_bits, true, bob_len);

    Bit *alice = new Bit[alice_len];
    Bit *bob = new Bit[bob_len];

    init(alice, alice_bits, alice_len, ALICE);
    init(bob, bob_bits, bob_len, BOB);
    Integer c(256, true, PUBLIC);
    if (flag & TPCF_OT_ONLY)
        return "";
    for (int i = 0; i < 512; ++i)
        alice[i] = alice[i] ^ bob[i];
    const long LOOP = 1;
    if (flag & TPCF_REAL_GC) {
        for (long loop = 0; loop < LOOP; ++loop) {
            sha256_cf.compute((block *)(c.bits),
                              (block *) alice, nullptr);
        }
    } else {
        CircuitFile cf{sha256_cf};
        for (long loop = 0; loop < LOOP; ++loop) {
            cf.compute((block *)(c.bits),
                       (block *) alice, nullptr);
        }
    }
    for (size_t i = 0; i < 256; ++i)
        c[i].reveal<bool>(BOB);
    delete []alice;
    delete []bob;
    return "";
}

Rt run_sort(const void *, const void *, int flag) {
    long n = std::max(std::max(4096L, ALICE_LEN), BOB_LEN);
    long N = n * 32;
    Bit *a = new Bit[N];
    Bit *b = new Bit[N];
    bool a_bits[N], b_bits[N];
    std::memset(a_bits, true, N);
    std::memset(b_bits, false, N);
    init(a, a_bits, N, ALICE);
    init(b, b_bits, N, BOB);
    if (flag & TPCF_OT_ONLY) {
        delete []a;
        delete []b;
        return "";
    }

    Integer *A = new Integer[n];
    Integer *B = new Integer[n];
    for (long i = 0; i < n; ++i) A[i] = Integer(32, &a[i * 32]);
    for (long i = 0; i < n; ++i) B[i] = Integer(32, &b[i * 32]);

    for (long i = 0; i < n; ++i) A[i] = A[i] ^ B[i];
    sort(A, n);
    for (long i = 0; i < n; ++i) A[i].reveal<string>(BOB);
    delete []A;
    delete []B;
    return ""; 
}

Rt run_modexp(const void *, const void *, int flag) {
    long alice_len = std::max(32L, ALICE_LEN);
    long bob_len = std::max(32L, BOB_LEN);
    Integer a(alice_len, 0, ALICE);
    Integer b(bob_len, 0, BOB);
    if (flag & TPCF_OT_ONLY) 
        return "";
    Integer c(alice_len, 5, PUBLIC);
    a.modExp(b, c).reveal<string>(BOB); 
    return "";
}

void run_alice(runner_t runner, const std::string &tag)
{
    const char *alice_input = "this-is-alice-input-it-might-be-dummy";
    g_party = ALICE;
    bool silent = true;
    std::vector<NetIO *> iov;
    for (int i = 0; i < MAX_PVC_ITERATION; ++i)
        iov.push_back(new NetIO(nullptr, PORT++, silent));
    NetIO *aio = new NetIO(nullptr, PORT++, silent);
    auto prt = std::make_shared<PVCGen<NetIO>>(iov, aio);
    NamedTimer timer(tag);
    timer.start();
    prt->run<Rt>(runner, alice_input);
    timer.stop();
    int64_t bytes = 0;
    iov.push_back(aio);
    for (auto io : iov) {
        bytes += io->counter;
        delete io;
    }
    printf("%ld %.4f\n", bytes, timer.usec / 1000.);
}

void run_bob(runner_t runner, const std::string &tag)
{
    const char *bob_input = "this-is-bob-input-it-might-be-dummy";
    std::map<std::string, std::string> ground_th{
        {"aes", "3f5b8cc9ea855a0afa7347d23e8d664e"},
        {"sha1", "92b404e556588ced6c1acd4ebf053f6809f73a93"},
        {"sha256", "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8"},
        {"add", "c"} };
#ifndef NDEBUG
    std::cout << "gnd = " << hex_to_binary(ground_th[tag]) << "\n";
#endif
    g_party = BOB;
    std::vector<NetIO *> iov;
    bool silent = true;
    const char *SERVER_IP = "127.0.0.1";
    for (int i = 0; i < MAX_PVC_ITERATION; ++i)
        iov.push_back(new NetIO(SERVER_IP, PORT++, silent));
    NetIO *aio = new NetIO(SERVER_IP, PORT++, true);
    auto prt = std::make_shared<PVCEva<NetIO>>(iov, aio);
    NamedTimer timer(tag);
    timer.start();
    prt->run<Rt>(runner, bob_input);
    timer.stop();
    int64_t bytes = 0;
    iov.push_back(aio);
    for (auto io : iov) {
        bytes += io->counter;
        delete io;
    }
    printf("%ld %.4f\n", bytes, timer.usec / 1000.);
}

const char *_usage = "./prg aes[sha1|sha256] alice[bob] [alen] [blen]";
int main(int argc, char **argv) {
    if (argc < 3) {
        printf("%s\n", _usage);
        return -1;
    }
    using gen_eva_t = std::function<void (runner_t, const std::string &)>;
    std::map<std::string, runner_t> circuits = {{"mult", run_mult_circut},
                                                {"aes", run_aes_circut},
                                                {"sha1", run_sha1_circut},
                                                {"sha256", run_sha256_circut},
                                                {"sort", run_sort},
                                                {"modexp", run_modexp},
                                                {"ham", run_hamming_distance},
                                                {"bench", run_bench}};
    std::map<std::string, gen_eva_t> parties = {{"alice", run_alice},
                                                {"bob", run_bob}};

    auto c = circuits.find(std::string(argv[1]));
    auto p = parties.find(std::string(argv[2]));
    if (c == circuits.end() || p == parties.end()) {
        printf("%s\n", _usage);
        return -1;
    }
    initialize_relic();
    if (argc > 3) ALICE_LEN = std::stol(argv[3], nullptr, 10);
    if (argc > 4) BOB_LEN = std::stol(argv[4], nullptr, 10);
    if (argc > 5) GATE = std::stol(argv[5], nullptr, 10);
    if (argc > 6) OUT_LEN = std::stol(argv[6], nullptr, 10);
    p->second(c->second, c->first);
    return 0;
}
