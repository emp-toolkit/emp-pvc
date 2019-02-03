# emp-pv
## Covert Security with Public Verifiability: Faster, Leaner, and Simpler
More details of the protocol can be found in the [paper](https://eprint.iacr.org/2018/1108).

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

## Installation

1. Install prerequisites using instructions [here](https://github.com/emp-toolkit/emp-readme).
2. Install [emp-tool](https://github.com/emp-toolkit/emp-tool).
3. Install [emp-ot](https://github.com/emp-toolkit/emp-ot).
4. git clone https://github.com/emp-toolkit/emp-pvc.git
5. cd emp-pvc && cmake . && sudo make install

## Test

* IF you want to test the code over two machines, type

  `./bin/test_pvc.cpp_exe aes alice [more opts]` on one machine and 

  `./bin/test_pvc.cpp_exe aes bob [more opts]` on the other.

  IP address is hardcoded in the test file (i.e., test/test_pvc.cpp). Please replace
  SERVER_IP variable to the real ip.


