# Third-party licenses

The signer WebAssembly (`packages/leokit-shielded-sign/pkg/leokit_shielded_sign_bg.wasm`) is built from the crates below. The list comes from `cargo tree --target wasm32-unknown-unknown -e normal,no-proc-macro` with the features this build enables, so build-time-only crates are left out.

Every license here is permissive and compatible with distributing the signer under MIT OR Apache-2.0. Each crate's license text, with its copyright notice, ships with its source on crates.io. Two notices are reproduced at the end of this file:

- `subtle`, which is BSD-3-Clause;
- libsecp256k1, the MIT-licensed C library that `secp256k1-sys` (CC0-1.0) compiles in.

`zcash_script` is Apache-2.0 only.

122 crates.

| Crate | Version | License |
| --- | --- | --- |
| aead | 0.6.1 | MIT OR Apache-2.0 |
| aes | 0.9.3 | MIT OR Apache-2.0 |
| arrayvec | 0.7.8 | MIT OR Apache-2.0 |
| bech32 | 0.11.1 | MIT |
| bellman | 0.15.0 | MIT OR Apache-2.0 |
| bip32 | 0.6.0 | Apache-2.0 OR MIT |
| bip39 | 2.2.2 | CC0-1.0 |
| bitcoin_hashes | 0.14.101 | CC0-1.0 |
| bitflags | 2.13.2 | MIT OR Apache-2.0 |
| bitvec | 1.1.1 | MIT |
| blake2b_simd | 1.0.5 | MIT |
| blake2s_simd | 1.0.5 | MIT |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| block-buffer | 0.12.1 | MIT OR Apache-2.0 |
| bls12_381 | 0.9.0 | MIT OR Apache-2.0 |
| bounded-vec | 0.9.0 | CC0-1.0 |
| bs58 | 0.5.1 | MIT OR Apache-2.0 |
| byteorder | 1.5.0 | Unlicense OR MIT |
| cbc | 0.2.1 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| chacha20 | 0.10.2 | MIT OR Apache-2.0 |
| chacha20poly1305 | 0.11.0 | Apache-2.0 OR MIT |
| cipher | 0.5.2 | MIT OR Apache-2.0 |
| cmov | 0.5.4 | Apache-2.0 OR MIT |
| console_error_panic_hook | 0.1.7 | Apache-2.0 OR MIT |
| constant_time_eq | 0.4.2 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| corez | 0.1.1 | MIT OR Apache-2.0 |
| cpubits | 0.1.1 | MIT OR Apache-2.0 |
| crunchy | 0.2.4 | MIT |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| crypto-common | 0.2.2 | MIT OR Apache-2.0 |
| ctutils | 0.4.3 | Apache-2.0 OR MIT |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| digest | 0.11.3 | MIT OR Apache-2.0 |
| either | 1.19.0 | MIT OR Apache-2.0 |
| equihash | 0.3.0 | MIT OR Apache-2.0 |
| equivalent | 1.0.3 | Apache-2.0 OR MIT |
| f4jumble | 0.1.2 | MIT OR Apache-2.0 |
| ff | 0.14.0 | MIT OR Apache-2.0 |
| fpe | 0.7.0 | MIT OR Apache-2.0 |
| funty | 2.0.0 | MIT |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| groth16 | 0.2.0 | MIT OR Apache-2.0 |
| group | 0.14.0 | MIT OR Apache-2.0 |
| halo2_gadgets | 0.6.0 | MIT OR Apache-2.0 |
| halo2_legacy_pdqsort | 0.1.0 | MIT OR Apache-2.0 |
| halo2_poseidon | 0.2.0 | MIT OR Apache-2.0 |
| halo2_proofs | 0.4.0 | MIT OR Apache-2.0 |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| hex-conservative | 0.2.3 | CC0-1.0 |
| hmac | 0.13.0 | MIT OR Apache-2.0 |
| hybrid-array | 0.4.15 | MIT OR Apache-2.0 |
| incrementalmerkletree | 0.9.0 | MIT OR Apache-2.0 |
| indexmap | 2.14.2 | Apache-2.0 OR MIT |
| inout | 0.2.3 | MIT OR Apache-2.0 |
| itoa | 1.0.18 | MIT OR Apache-2.0 |
| js-sys | 0.3.77 | MIT OR Apache-2.0 |
| jubjub | 0.11.1 | MIT OR Apache-2.0 |
| lazy_static | 1.5.1 | MIT OR Apache-2.0 |
| libm | 0.2.16 | MIT |
| maybe-rayon | 0.1.1 | MIT |
| memchr | 2.8.3 | Unlicense OR MIT |
| memuse | 0.2.2 | MIT OR Apache-2.0 |
| nonempty | 0.11.0 | MIT |
| num-bigint | 0.5.1 | MIT OR Apache-2.0 |
| num-integer | 0.1.47 | MIT OR Apache-2.0 |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| orchard | 0.16.0 | MIT OR Apache-2.0 |
| pairing | 0.24.0 | MIT OR Apache-2.0 |
| pasta_curves | 0.6.1 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| poly1305 | 0.9.1 | Apache-2.0 OR MIT |
| radium | 0.7.0 | MIT |
| rand | 0.10.3 | MIT OR Apache-2.0 |
| rand_core | 0.10.1 | MIT OR Apache-2.0 |
| reddsa | 0.6.1 | MIT OR Apache-2.0 |
| redjubjub | 0.9.0 | MIT OR Apache-2.0 |
| ripemd | 0.1.3 | MIT OR Apache-2.0 |
| ripemd | 0.2.0 | MIT OR Apache-2.0 |
| sapling-crypto | 0.9.0 | MIT OR Apache-2.0 |
| secp256k1 | 0.33.1 | CC0-1.0 |
| secp256k1-sys | 0.14.1 | CC0-1.0 |
| secrecy | 0.8.0 | Apache-2.0 OR MIT |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde-wasm-bindgen | 0.6.5 | MIT |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| sha2 | 0.11.1 | MIT OR Apache-2.0 |
| sinsemilla | 0.2.0 | MIT OR Apache-2.0 |
| spin | 0.9.9 | MIT |
| static_assertions | 1.1.0 | MIT OR Apache-2.0 |
| subtle | 2.6.1 | BSD-3-Clause |
| tap | 1.0.1 | MIT |
| thiserror | 2.0.21 | MIT OR Apache-2.0 |
| tinyvec | 1.13.3 | Zlib OR Apache-2.0 OR MIT |
| tracing | 0.1.44 | MIT |
| tracing-core | 0.1.36 | MIT |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| uint | 0.9.5 | MIT OR Apache-2.0 |
| unicode-normalization | 0.1.25 | MIT OR Apache-2.0 |
| universal-hash | 0.6.1 | MIT OR Apache-2.0 |
| wasm-bindgen | 0.2.100 | MIT OR Apache-2.0 |
| web-sys | 0.3.77 | MIT OR Apache-2.0 |
| wyz | 0.5.1 | MIT |
| zcash_address | 0.14.0 | MIT OR Apache-2.0 |
| zcash_encoding | 0.5.0 | MIT OR Apache-2.0 |
| zcash_keys | 0.17.0 | MIT OR Apache-2.0 |
| zcash_note_encryption | 0.5.1 | MIT OR Apache-2.0 |
| zcash_primitives | 0.31.0 | MIT OR Apache-2.0 |
| zcash_proofs | 0.31.0 | MIT OR Apache-2.0 |
| zcash_protocol | 0.11.0 | MIT OR Apache-2.0 |
| zcash_script | 0.6.0 | Apache-2.0 |
| zcash_spec | 0.2.1 | MIT OR Apache-2.0 |
| zcash_transparent | 0.11.0 | MIT OR Apache-2.0 |
| zeroize | 1.9.1 | Apache-2.0 OR MIT |
| zip32 | 0.3.0 | MIT OR Apache-2.0 |
| zmij | 1.0.23 | MIT |

## subtle (BSD-3-Clause)

```
Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## libsecp256k1 (MIT), bundled by secp256k1-sys

```
Copyright (c) 2013 Pieter Wuille

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
