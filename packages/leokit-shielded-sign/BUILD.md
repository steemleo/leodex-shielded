# Reproducing the signer build

The signer build is reproducible. Built from this source with the toolchain below, it gives byte-for-byte the files in [`pkg/`](pkg), which are also the files leodex.io serves at `/wasm/leokit-shielded-sign/v0.0.8/`.

## Expected output (v0.0.8)

```
8e3431e662948686ef546d96ff441ad3221354bd8ec3487f3d1388330710a855  leokit_shielded_sign_bg.wasm
08588f805a85d86dd1074a24b5f86039a1e33edd7a19d2cb1adc095994b8c819  leokit_shielded_sign.js
```

## Toolchain

| Tool | Version | Notes |
| --- | --- | --- |
| rustc | 1.94.1 | Pinned in `rust-toolchain.toml`, with the `wasm32-unknown-unknown` target |
| wasm-bindgen-cli | 0.2.100 | Must match the crate's `wasm-bindgen` pin: `cargo install wasm-bindgen-cli --version 0.2.100 --locked` |
| clang with a wasm32 backend | Homebrew LLVM 23.1.2 on macOS | `secp256k1-sys` compiles C for wasm32, so the clang version can change the bytes. Xcode's clang has no wasm32 backend |

Dependencies are locked in `Cargo.lock`. The Zcash crates that build and prove transactions are also pinned to exact versions in `Cargo.toml`.

## Build

From `packages/leokit-shielded-sign`:

```bash
just build
```

That runs the following, which also rewrites `pkg/SHA256SUMS`:

```bash
CRATE=$PWD
TD=${CARGO_TARGET_DIR:-$PWD/target}
LLVM=/opt/homebrew/opt/llvm   # any clang with the wasm32 target

CARGO_TARGET_DIR=$TD \
RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$CRATE=/leokit-shielded-sign --remap-path-prefix=$TD=/target" \
CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=$HOME/.cargo=/cargo -ffile-prefix-map=$CRATE=/leokit-shielded-sign" \
CC_wasm32_unknown_unknown=$LLVM/bin/clang \
AR_wasm32_unknown_unknown=$LLVM/bin/llvm-ar \
cargo build --lib --release --target wasm32-unknown-unknown

wasm-bindgen --target web --out-dir pkg $TD/wasm32-unknown-unknown/release/leokit_shielded_sign.wasm
cd pkg && shasum -a 256 leokit_shielded_sign_bg.wasm leokit_shielded_sign.js > SHA256SUMS
```

If your build matches, `git status` shows no change under `pkg/`.

The path remapping is what makes the output independent of your home directory, checkout location and target directory. Without it, the binary embeds local paths and the hashes won't match.

## What we've verified

- Two clean builds from different checkout paths into different target directories gave identical `.wasm`, `.js` and `.d.ts` files.
- The wasm contains no local filesystem paths.
- The hashes above match `pkg/SHA256SUMS` and the files served by leodex.io.

So far we've confirmed this on macOS (Apple silicon, Homebrew LLVM 23.1.2). We haven't confirmed a Linux build yet. If you build on Linux and get different hashes, please open an issue with your clang and rustc versions.

## Notes

- `wasm-opt` is off. The release profile favors proving speed (opt-level 3, thin LTO, one codegen unit) over size.
- A published version is never overwritten. Any change to the signer ships under a new version and a new path.
- The `.d.ts` files aren't in `SHA256SUMS`, because the site loads only the wasm and the JS glue.
