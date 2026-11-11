# LeoDex shielded ZEC

The browser code behind private ZEC on [LeoDex](https://leodex.io).

- **`leokit-shielded-sign`** is a Rust crate compiled to WebAssembly. It builds, proves and signs Zcash Sapling transactions inside your browser. Your seed phrase and spending key never leave it.
- **`leokit-shielded-sdk`** is a TypeScript client for the LeoDex shielded server. Before it sends your viewing key anywhere, it checks an AMD SEV-SNP attestation report. That report proves the server is genuine AMD hardware running the exact image we pinned. Your viewing key, the sensitive fields of scan requests, and the server's replies to them are then end-to-end encrypted.

This is the code leodex.io runs today. Signer v0.0.8 has been live since November 2, 2026, and it supports NU6.3 and NU7 (ZIP 259, activation at block 3,543,405).

| Package | Language | License | What it does |
| --- | --- | --- | --- |
| [`packages/leokit-shielded-sign`](packages/leokit-shielded-sign) | Rust → WASM | MIT OR Apache-2.0 | Derives keys, builds and proves v5 transactions, computes the ZIP 317 fee |
| [`packages/leokit-shielded-sdk`](packages/leokit-shielded-sdk) | TypeScript | MIT | Attests the server, seals your viewing key (HPKE), fetches your notes, broadcasts |

## How private ZEC works on LeoDex

1. The SDK asks the shielded server for a fresh attestation report and verifies it in the browser, against AMD's root key and the enclave measurement we pinned.
2. It encrypts your viewing key to a public key bound into that report, whose private key is created inside the attested enclave.
3. Inside the enclave, the server scans the chain with your viewing key and returns your notes and their Merkle witnesses. Replies are encrypted end to end under a key from the same handshake.
4. The signer builds the transaction and generates the Groth16 proofs in your browser, then signs with your spending key.
5. The SDK broadcasts the finished transaction.

The server gets view-only material, sealed to a key created inside the attested enclave. It can never spend. The full picture, including what each party can see, is in [docs/how-it-works.md](docs/how-it-works.md). Every attestation check is listed in [docs/attestation.md](docs/attestation.md).

## Check what leodex.io serves

The site loads the signer from a fixed, versioned path and checks its SHA-256 against a hash pinned in the site's source before running it. You can check the same files against this repo:

```bash
curl -sO https://leodex.io/wasm/leokit-shielded-sign/v0.0.8/leokit_shielded_sign_bg.wasm
curl -sO https://leodex.io/wasm/leokit-shielded-sign/v0.0.8/leokit_shielded_sign.js
shasum -a 256 leokit_shielded_sign_bg.wasm leokit_shielded_sign.js
cat packages/leokit-shielded-sign/pkg/SHA256SUMS
```

Both pairs of hashes should match:

```
8e3431e662948686ef546d96ff441ad3221354bd8ec3487f3d1388330710a855  leokit_shielded_sign_bg.wasm
08588f805a85d86dd1074a24b5f86039a1e33edd7a19d2cb1adc095994b8c819  leokit_shielded_sign.js
```

To go one step further, build the signer yourself and get the same bytes. The steps are in [packages/leokit-shielded-sign/BUILD.md](packages/leokit-shielded-sign/BUILD.md).

## What is not in this repo

- **The shielded server** (the chain scanner and witness service) and **the enclave image** it boots. The SDK checks that the server runs the image we pinned, but you can't rebuild that image from this repo yet. On the server side you are trusting AMD's hardware and our image, which is the main limit of this design.
- **The leodex.io web app.** It uses both packages as they are here.

## Build and test

Signer (needs Rust 1.94.1, pinned in `rust-toolchain.toml`):

```bash
cd packages/leokit-shielded-sign
ZCASH_PARAMS_DIR=~/.zcash-params cargo test --features tools
```

That runs 20 tests, including real Groth16 proving at heights around NU7. The proving tests need the Sapling parameters. Without them, they print `SKIP` and return early, so check the output. The package README says where to get the parameters.

SDK (needs Node 20+):

```bash
cd packages/leokit-shielded-sdk
npm install
npm test            # 49 tests, no network
npm run typecheck
```

Each package README has the details.

## Security

Please report vulnerabilities privately. [SECURITY.md](SECURITY.md) explains how.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We follow the librustzcash style guides.

## License

The signer is licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option, the same as the Zcash crates it builds on. The SDK is licensed under [MIT](LICENSE-MIT). Third-party crates compiled into the signer are listed in [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

Copyright 2026 LeoDex.
