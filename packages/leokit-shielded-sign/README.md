# leokit-shielded-sign

Builds, proves and signs Zcash Sapling transactions in the browser. It's a Rust crate compiled to WebAssembly with `wasm-bindgen`, and it's the signer behind private ZEC sends on [leodex.io](https://leodex.io).

- The spending key is derived inside the WASM module and never leaves it. The caller passes in the seed phrase, which is never returned or sent anywhere. No call makes a network request.
- All the cryptography comes from the official Zcash crates (`zcash_primitives`, `sapling-crypto`, `zcash_keys`). The crates that build and prove transactions are pinned to exact versions, and `Cargo.lock` locks the rest.
- It builds v5 transactions only, which are valid under NU6.3 and NU7.
- It's mainnet only. Testnet addresses are refused.

## API

The compiled package is in [`pkg/`](pkg). These are its main exports:

| Function | Returns |
| --- | --- |
| `build_sapling_tx_v5(args_json, spend_params, output_params)` | `{ tx_hex, txid, fee_zats }`, a signed transaction ready to broadcast |
| `derive_default_unified_address(seed_phrase, account)` | The account's default unified address |
| `inspect_address(addr)` | JSON: the address kind, its receivers, and whether this signer can pay it |
| `note_witness_root(note_json)` | The Merkle root a note's witness implies, so stale witnesses can be caught before proving |
| `consensus_branch_id_for_height(height, nu7_activation_height?)` | The consensus branch ID for a mainnet height |
| `signer_info()` | JSON: signer version, transaction version, and every network upgrade it knows |
| `leokit_sign_version()` | The crate version |

```js
import init, { build_sapling_tx_v5 } from "./pkg/leokit_shielded_sign.js";

await init();
const tx = build_sapling_tx_v5(JSON.stringify(args), spendParams, outputParams);
// tx.tx_hex, tx.txid, tx.fee_zats
```

In production, load the module through `fetchVerifiedWasm` from `leokit-shielded-sdk`, which refuses bytes that don't match a pinned SHA-256.

### `build_sapling_tx_v5` input

```jsonc
{
  "seed_phrase": "…24 words…",
  "account": 0,
  "anchor_hex": "…",            // Sapling tree root the witnesses were computed against
  "target_height": 3543500,     // height the transaction is built for
  "notes": [{
    "recipient": "…",           // hex of the raw 43-byte payment address
    "amount_zats": 150000000,
    "rseed": "01…",             // 33 bytes hex: version byte + rseed
    "position": 123456,         // leaf position in the commitment tree
    "witness": ["…", "…"]       // 32 sibling hashes, leaf to root
  }],
  "outputs": [{
    "recipient": "u1…",         // u1 (Sapling receiver), zs1, t1 or t3
    "amount_zats": 100000000,
    "memo": "optional; dropped on transparent outputs"
  }],
  "fee_zats": 0,                // required, but ignored: the signer computes the ZIP 317 fee
  "nu7_activation_height": 3543405,  // optional cross-check
  "memo_note": {                // optional: zero-value memo output for Maya swaps
    "recipient_ua": "u1…",
    "memo_text": "=:e:0x…"
  }
}
```

`spend_params` and `output_params` are the bytes of the standard Sapling proving parameters (see [Sapling parameters](#sapling-parameters)).

Change goes back to the account's default Sapling address. The returned `fee_zats` is the fee the transaction actually pays.

### Errors

Errors are thrown as JavaScript `Error`s whose `message` starts with a stable code, so callers can branch on the code without parsing prose.

| Code | Meaning |
| --- | --- |
| `INVALID_INPUT` | The arguments didn't parse or are out of range, or a caller-supplied NU7 height disagrees with ZIP 259 |
| `INVALID_RECIPIENT` | Not a valid mainnet Zcash address |
| `NO_SAPLING_RECEIVER` | A unified address with no Sapling receiver (Orchard-only addresses aren't supported yet) |
| `UNSUPPORTED_RECIPIENT` | A TEX address (ZIP 320) |
| `INSUFFICIENT_FUNDS` | The notes can't cover the outputs plus the fee, or what's left over is too small to pay for its own change output |
| `ANCHOR_MISMATCH` | A witness doesn't lead to `anchor_hex`. Refresh the notes and try again |
| `UPGRADE_IMMINENT` | The target height is 1–3 blocks before NU7. The expiry would be clamped to the block before activation, which is too soon for nodes to accept |
| `KEY_DERIVATION` | Key derivation from the seed failed |
| `BUILD_FAILED` | Anything else from the builder, including the self-checks below |

## Network upgrades

- **NU7 is built in.** The mainnet activation height (3,543,405, ZIP 259) and branch ID (`0x77190ad9`) come from `zcash_protocol 0.11.0`, and the signer also hardcodes the height. If the crate ever reports a different height, `build_sapling_tx_v5` refuses with `BUILD_FAILED` and `consensus_branch_id_for_height` returns 0. A caller can pass `nu7_activation_height` as a cross-check, and any other value is refused.
- **Expiry.** Before NU7, a transaction expires 40 blocks after its target height, clamped to the block before activation so a pre-upgrade transaction can't outlive its branch. From NU7 onward the delta is 120 blocks (ZIP 218).
- **Self-check.** After building, the signer re-reads the transaction and confirms it's v5, carries the branch ID for its target height, and has the expiry it set. If any of that is off, it returns `BUILD_FAILED` instead of a transaction.

## Fees

The signer pays the ZIP 317 fee, counting Sapling padding: a Sapling bundle always has at least two outputs, and transparent outputs add to the count. It works out the fee for the shape with and without a change output and picks the one that balances.

## Sapling parameters

Proving needs the standard Sapling parameters. Get them from `https://download.z.cash/downloads/` and check the hashes:

```
8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13  sapling-spend.params
2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4  sapling-output.params
```

## Building

`just build` produces `pkg/` and `pkg/SHA256SUMS`. The build is reproducible: the same source gives the same bytes. [BUILD.md](BUILD.md) has the toolchain, the exact command and the hashes for v0.0.8.

## Testing

```bash
ZCASH_PARAMS_DIR=~/.zcash-params cargo test --features tools
```

There are 20 tests. They cover:

- the branch schedule and expiry around NU7;
- address classification;
- fee shapes;
- insufficient funds;
- stale witnesses.

They also build real transactions with Groth16 proofs at seven heights from 100 blocks before NU7 to 50 after, and for every fee shape on both branches, and check each one with the native verifier in [`src/verify.rs`](src/verify.rs). That verifier keeps its own copies of the heights, branch IDs and expiry rule, so it checks the signer rather than repeating its code.

Without the Sapling parameters, the proving tests print `SKIP` and return early.

`node scripts/verify-release.mjs` is the gate we run before publishing a build. It builds transactions through the WASM, decodes their headers, verifies them natively, and confirms the expected refusals.

The test fixtures come from the public BIP-39 test phrase ("abandon … about") and a synthetic commitment tree. Run `cargo run --example gen_fixtures` to regenerate them.

## Scope

- **Sapling only.** The signer spends Sapling notes and pays Sapling or transparent outputs. Orchard is not supported yet.
- **Unified addresses** from ZIP 316 revision 1. Revision 2 addresses aren't classified yet.

## License

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE). [`src/prover.rs`](src/prover.rs) adapts `LocalTxProver` from `zcash_proofs` (MIT OR Apache-2.0, the Zcash developers).
