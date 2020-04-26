# emp-pvc [![Build Status](https://travis-ci.org/emp-toolkit/emp-pvc.svg?branch=master)](https://travis-ci.org/emp-toolkit/emp-pvc)

## Covert Security with Public Verifiability: Simpler, Faster, and Leaner
More details of the protocol can be found in the [paper](https://eprint.iacr.org/2018/1108).

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

## Installation

1. Install prerequisites using instructions [here](https://github.com/emp-toolkit/emp-readme).
2. Install relic using script [here](https://github.com/emp-toolkit/emp-readme/blob/master/scripts/install_relic.sh)
3. Install [emp-tool](https://github.com/emp-toolkit/emp-tool) at commit `50c01ba99e5d257de05ef0e74ce6a0294a9ff471`. When cmake, use `cmake -DTHREADING=on .`
3. Install [emp-ot](https://github.com/emp-toolkit/emp-ot) at `15fb731e528974bcfe5aa09c18bb16376e949283`.
4. git clone https://github.com/emp-toolkit/emp-pvc.git
5. cd emp-pvc && cmake . && make

## Test

* IF you want to test the code over two machines, type

  `./bin/test_pvc.cpp_exe aes alice [more opts]` on one machine and 

  `./bin/test_pvc.cpp_exe aes bob [more opts]` on the other.

  IP address is hardcoded in the test file (i.e., test/test_pvc.cpp). Please replace
  SERVER_IP variable to the real ip.

## Parameters

* Change the `MAX_PVC_ITERATION` constant in `emp-pvc/common.h` to modify the deference factor, i.e., the `lambda` parameter in the paper. For example, for `MAX_PVC_ITERATION = k`, we have `(k-1)/k` probability to detect the malicious generator.

## Two-stage PVC circuits coding

For the sake of efficiency, we use a two-stage programming for writing the pvc programs.
The main difference of writing pvc programs and the semi-honest programs is that, in pvc programs,
the total number of input wires should be set in the beginning part of the codes.
That is because, to simulate OTs, it requires to know the number of input wires at the beginning.
We can draw an analogy with the old c89 codes (which requires to declare all variables at first) and new c98 codes (which allows to declare new variables when we want).

We have an flag variable i.e., `TPCF_OT_ONLY` to indicate that we are in the first stage.
The TPCF_OT_ONLY is set by the emp-pvc framework internally, so we can easily modify any semi-honest programs built on the emp-toolkit
to its pvc counterpart by four steps.

1: adding a new argument in the signature to receive the TPCF_OT_ONLY flag

2: moving all wires initialization in first parts to programs.

3: adding an if-then-return statement after the wires initialization codes which will leave the program when the flag passed in is TPCF_OT_ONLY.

4: Indeed, there is one more devil in the details. We leverage multi-threading for a better efficiency. 
   As a result, when we use a global CircuitFile to compute the GC, we need to copy the CircuitFile object. 

Take the following circuits as the example.

```
// the 3rd flag to receive TPCF_OT_ONLY
void run_aes_circut(const void *al, const void *bb, int flag)
{
    // The input wires initialization.
    long alice_len = std::max(128L, ALICE_LEN);
    long bob_len = std::max(128L, BOB_LEN);
    Bit *a = new Bit[alice_len];
    Bit *b = new Bit[bob_len];
    init(a, al, alice_len, ALICE);
    init(b, bb, bob_len, BOB);
    Integer c(128, 0, PUBLIC);

    // Return if we are doing OT simulation.
    if (flag & TPCF_OT_ONLY) {
        delete []a;
        delete []b;
        return ;
    }

    // Run gc from here. It might be threading, so we copy the gloabl gc file, aes_cf.
    CircuitFile cf{aes_cf};
    cf.compute((block *)c.bits, (block *)a, (block *)b);
    for (int i = 0; i < 128; ++i)
        c[i].reveal<bool>(BOB);
    delete []a;
    delete []b;
    return ;
}
```
