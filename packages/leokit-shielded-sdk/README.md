# leokit-shielded-sdk

TypeScript client for the LeoDex shielded server, the service that finds your Sapling notes for the browser wallet on [leodex.io](https://leodex.io).

Your seed and spending key stay in the browser. The SDK's job is to make sure your viewing key only ever reaches the attested server, and to fetch your notes:

- **Attestation.** Before the first viewing key is sent, it verifies the server's AMD SEV-SNP report: the chain to AMD's pinned root, the launch measurement, a fresh nonce, the guest policy, the firmware floor, and a binding to the server's encryption key. The details are in [docs/attestation.md](../../docs/attestation.md).
- **End-to-end encryption.** It seals the viewing key with HPKE (RFC 9180) to the attested key, encrypts sensitive request fields, and refuses any reply that isn't sealed under the request's key.
- **Pinned WASM.** `fetchVerifiedWasm` downloads a WebAssembly module, such as the signer, and checks its SHA-256 before anything compiles.

It runs in browsers and in any runtime with `fetch` and WebCrypto. Its only dependencies are `@hpke/core`, `@hpke/chacha20poly1305` and `@noble/ciphers`.

## Quick start

```ts
import { ShieldedClient, setTrustedMeasurement, setKdsMirror } from "leokit-shielded-sdk";

// Once, at startup: the enclave image(s) you trust, the silicon family,
// and a minimum firmware level.
setTrustedMeasurement(["<96 hex chars>"], "Genoa", { bootloader: 9, tee: 0, snp: 23, microcode: 72 });

const client = new ShieldedClient({ baseUrl: "https://shielded.leokit.dev" });

// Attests on first use, then seals the viewing key to the attested key.
const delta = await client.scannerDelta({ ufvk, fromHeight, knownNullifiers });
// delta.notes come with Merkle witnesses and delta.anchor, ready for the signer.

const outcome = await client.txBroadcast(signedTxHex);
// outcome.error_code and outcome.error_message carry the node's answer.
```

## API

| Export | What it does |
| --- | --- |
| `ShieldedClient` | Typed client for the server API. `attest()` runs automatically before the first sealed request |
| `client.scannerDelta(args)` | Your notes since a height, with witnesses and the anchor. The viewing key and the sensitive fields are sealed |
| `client.scannerScan(args)` | A full scan from the wallet's birthday height. Sealed like `scannerDelta` |
| `client.walletAddress(ufvk)` | The unified address and receiver types for a viewing key, over a sealed request |
| `client.txBroadcast(txHex)` | Relays a signed transaction to the network |
| `client.health()`, `scannerStatus()`, `scannerTip()` | Server and scanner status |
| `setTrustedMeasurement(measurements, product?, minTcb?)` | Process-wide attestation settings, so no call site can forget them |
| `verifyEnclave(client, opts)` | The attestation check on its own. Returns `{ ok, reasons, attestedPubkey, measurement, chainVerified, mode, tcb, policy }` |
| `setKdsMirror(url, timeoutMs?)` | Asks a mirror of AMD's key server before AMD itself. The mirror is untrusted, and everything it serves is verified |
| `setVcekCacheStorage(storage)` | Keeps verified AMD certificates across page loads (`localStorage`-shaped). They are re-verified on every use |
| `fetchVerifiedWasm(url, sha256)` | Fetches WASM bytes and throws unless the SHA-256 matches |
| `sealUfvk`, `sealUfvkToKey`, `decryptResponse` | The HPKE layer, for advanced use |

### Errors

| Error | When |
| --- | --- |
| `ShieldedAttestationError` | Attestation failed. `reasons` lists every failed check. The client won't retry for 60 seconds (`attestRetryAfterMs`) |
| `ShieldedReplyIntegrityError` | A reply to a sealed request was unsealed or didn't decrypt. It's never read as data |
| `ShieldedHttpError` | The server returned an HTTP error. `status` and `payload` are attached |

## Security notes

- **Always configure a measurement.** Without one, the client logs a warning and sends the viewing key to an unattested server key. That mode is for local development against a server that can't attest.
- **Only viewing material crosses the wire.** A viewing key shows your shielded history but can't spend. The seed and spending key never enter this package.
- **Hosting the SDK yourself?** Pin the signer's hash with `fetchVerifiedWasm`. Don't use streaming instantiation: the bytes compile before they can be checked.

## Development

```bash
npm install
npm test            # vitest, 49 tests, no network
npm run typecheck   # tsc --noEmit, strict
```

The attestation tests build synthetic AMD-style certificate chains at runtime. They cover forged signatures, wrong measurements, replayed nonces, debug policy, VMPL, the TCB floor, certificate dates, mirror fallback and caching.

## License

MIT. See [LICENSE-MIT](../../LICENSE-MIT).
