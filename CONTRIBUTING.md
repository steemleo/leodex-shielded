# Contributing

Thanks for looking. This code derives keys and signs real ZEC transactions, so we review every change slowly and on purpose.

## Setup

```bash
git clone https://github.com/steemleo/leodex-shielded.git && cd leodex-shielded

# Signer: Rust 1.94.1 is pinned in rust-toolchain.toml
cd packages/leokit-shielded-sign
ZCASH_PARAMS_DIR=~/.zcash-params cargo test --features tools
cargo clippy --all-targets --features tools

# SDK: Node 20+
cd ../leokit-shielded-sdk
npm install && npm test && npm run typecheck
```

The proving tests need the Sapling parameters. The [signer README](packages/leokit-shielded-sign/README.md#sapling-parameters) says where to get them, with their hashes. Without them those tests print `SKIP`, so a green run without the parameters proves less than it looks like.

Building the WASM itself needs a clang with a wasm32 backend. See [BUILD.md](packages/leokit-shielded-sign/BUILD.md).

## Style

We follow the [librustzcash contribution guide](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md) as our primary reference. In short:

- **Type safety first.** Make invalid states unrepresentable. Prefer newtypes and enums over bare integers, strings and booleans in anything that crosses a module boundary. Avoid `usize` except for indexing.
- **Errors are values.** Return `Result` and keep the stable error-code prefixes (`ANCHOR_MISMATCH:`, `INSUFFICIENT_FUNDS:`, …). Callers branch on them. No `unwrap` or `expect` in the signing path.
- **Side effects are explicit.** Randomness comes from one place (`os_rng`). Nothing in the signer touches the network, the clock or storage.
- **Serialization.** The signer's JSON input is an ephemeral wire format between the SDK and the signer, which librustzcash's serialization rules allow. Anything that gets stored must be versioned.
- **Public API changes** need full rustdoc or TSDoc, and a `CHANGELOG.md` entry in the same commit.

For the TypeScript SDK, the same ideas apply: strict mode stays on, and errors are typed classes.

Not all existing code meets this yet. For example, the signer's errors are coded strings rather than enums, because they cross the WASM boundary as JavaScript errors. New code should meet it, and style upgrades to old code go in their own commits, separate from functional changes.

## Rules that don't bend

- **Spending keys never leave the signer.** Seed phrases, spending keys and viewing keys never appear in logs, errors, panics or return values. Viewing keys leave the browser only sealed to an attested key, except in the development mode below.
- **Fail closed.** If a check can't complete (attestation, hash pin, anchor, branch ID), the operation stops. The one warn-and-continue path is the SDK's development mode with no measurement configured, and it must never reach a production build.
- **No silent consensus changes.** Heights, branch IDs, expiry rules and fee rules change only with a test that pins the new value. The native verifier in `src/verify.rs` keeps its own copy of the heights, branch IDs and expiry rule, so the two must agree. It reuses the signer's `zip317_fee`, so fee changes are pinned by `zip317_fee_counts_sapling_padding`.
- **Pinned dependencies stay pinned.** The Zcash protocol crates (`zcash_primitives`, `zcash_protocol`, `zcash_proofs`, `zcash_keys`, `zcash_address`, `zcash_transparent`, `sapling-crypto`, `orchard`) use exact versions (`=x.y.z`), and `Cargo.lock` pins the rest. Bumping one is its own pull request, with the reason and the upstream changelog linked.
- **A published signer version is immutable.** Any change to the WASM ships as a new version under a new path, with new hashes in `pkg/SHA256SUMS`.

## Commits and pull requests

- Commits are discrete semantic changes, with a short title (under about 120 characters) and a body that explains why. No "work in progress" commits in a pull request.
- To fix a bug, add the failing test first, in its own commit, then the fix.
- One concern per pull request.
- Say how you tested. For signer changes, say whether you ran the proving tests with the parameters present.
- Changes to attestation (`attestation.ts`), sealing (`e2e.ts`), WASM pinning (`wasm-verify.ts`) or transaction building (`lib.rs`) get the closest review.

**How changes land.** This project has a single maintainer of record, so every published artifact traces to one accountable author. We review pull requests in the open. Accepted changes are committed by the maintainer, and the contributor is credited by name in `CHANGELOG.md` and in the pull request. A CI check enforces this, so outside pull requests show a failed authorship check. That's expected and doesn't block review.

## Security issues

Report them privately. See [SECURITY.md](SECURITY.md). Never open a public issue for anything exploitable.
