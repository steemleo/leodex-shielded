# How private ZEC works on LeoDex

LeoDex has a shielded ZEC wallet in the browser: no install and no account. The hard part of a browser wallet is finding your notes. To find them yourself, the page would have to trial-decrypt every shielded output since your wallet's birthday, which is slow on a phone. We split the work instead:

- **Scanning happens on a server, inside an AMD SEV-SNP confidential VM.** The browser gives that VM a viewing key, but only after checking an attestation report.
- **Spending happens in the browser.** The seed phrase and spending key stay on your device. The proofs and signatures are made there too, and leave only inside the finished transaction.

## The parties

| Party | Holds | Can see |
| --- | --- | --- |
| Your browser | Seed phrase, spending key, viewing key | Everything about your wallet |
| Signer (WASM, in your browser) | Seed and spending key, while building a transaction | The transaction it builds |
| Shielded server (in the enclave) | Your viewing key | Your incoming and outgoing shielded notes, and the transactions you broadcast through it |
| Anything between the browser and the enclave | Nothing | Sealed envelopes with their sizes and timing, which endpoints you call, your IP address, and the raw transaction when you broadcast it |
| The Zcash network | — | What any Sapling transaction shows: the number of spends and outputs, the fee and the expiry height. A transparent output (a t-address, or a Maya deposit) shows its amount and address |

## One send, step by step

```mermaid
sequenceDiagram
    participant B as Browser (web app + SDK)
    participant S as Signer (WASM)
    participant E as Shielded server (SEV-SNP)
    participant A as AMD KDS
    participant Z as Zcash network

    B->>E: GET /attestation?nonce=<32 random bytes, hex>
    E-->>B: SNP report + HPKE public key
    B->>A: VCEK and cert chain (if not cached; via a mirror if set)
    A-->>B: Certificates
    Note over B: Verify chain to the pinned AMD root,<br/>report signature, measurement, nonce,<br/>policy, TCB floor, key binding
    B->>E: POST /scanner/delta (viewing key sealed to the attested key)
    E-->>B: Notes, witnesses, anchor (sealed reply)
    B->>S: Seed, notes, witnesses, anchor, outputs
    Note over S: Derive keys, build v5 tx,<br/>prove (Groth16), sign
    S-->>B: Raw transaction + txid
    B->>E: POST /tx/broadcast
    E->>Z: Relay
```

### 1. Attest

The SDK makes 32 random bytes and asks the server for an attestation report bound to them. The AMD secure processor signs that report, not the server software. Among other things, it carries:

- the nonce, so an old report can't be replayed;
- the launch measurement, a SHA-384 of the exact image the VM booted;
- the SHA-256 of the server's HPKE public key, so the key can't be swapped out in transit;
- the guest policy, the privilege level (VMPL) and the firmware versions (TCB).

The SDK checks the signature against AMD's certificate chain and pins AMD's root key in its source, so it never trusts a root someone else hands it. If any check fails, nothing is sent. The full list is in [attestation.md](attestation.md).

### 2. Seal the viewing key

The SDK encrypts your unified full viewing key with HPKE (RFC 9180: X25519, HKDF-SHA256, ChaCha20-Poly1305) to the key bound into the report. The same handshake exports two more keys: one to encrypt the request's sensitive fields (for example, which notes you already know about) and one for the reply.

TLS ends before the enclave, so we don't rely on it for privacy. Anything between your browser and the enclave sees only ciphertext for the viewing key, the sensitive request fields and the replies to them. If a reply arrives unsealed, or doesn't decrypt under this request's key, the SDK refuses it.

### 3. Scan

Inside the enclave, the server decrypts the viewing key, scans its copy of the chain for your notes, and returns each unspent note with its Merkle witness and the tree anchor.

### 4. Build and sign in the browser

The web app hands the signer your seed phrase, the notes, the witnesses, the anchor and the outputs you want. The signer:

- derives the Sapling spending key (ZIP 32) for the account;
- checks that every witness leads to the anchor before it spends any time proving;
- builds a v5 transaction with the official Zcash crates (`zcash_primitives`, `sapling-crypto`), using the consensus branch for the target height and the fee from ZIP 317;
- generates the Groth16 spend and output proofs, then signs.

The caller passes in the Sapling proving parameters. The signer never fetches anything itself.

### 5. Broadcast

The SDK sends the raw transaction to the server, which relays it to the network. The broadcast isn't sealed: the transaction becomes public the moment it's mined, so the request carries nothing the chain won't show. It does tie that transaction to your IP address for anyone watching the connection, as with any wallet that broadcasts through a server.

## What you are trusting

- **AMD SEV-SNP.** If the hardware or AMD's keys are compromised, attestation can be faked. Any SEV-SNP system has this trust root.
- **Our enclave image.** The SDK proves the server runs the image we pinned, but that image isn't published yet. A bug or backdoor in it could reveal your viewing key, which shows your shielded history. It can't move your funds: spending needs the spending key, and that never leaves your browser.
- **This code, in your browser.** Check the hashes in the [README](../README.md) or rebuild the signer yourself.

## Recipients

| Address | Result |
| --- | --- |
| Unified address with a Sapling receiver (`u1…`) | Shielded output to the Sapling receiver |
| Sapling address (`zs1…`) | Shielded output |
| Transparent address (`t1…`, `t3…`) | Deshielding output. The amount and recipient are public onchain |
| TEX address (ZIP 320) | Refused, because it needs a transparent-source transaction |
| Unified address with only an Orchard receiver | Refused. The signer is Sapling-only for now |
| Any non-mainnet address | Refused |

## Swaps into Maya

For Maya Protocol's shielded-memo deposits, the signer can add one extra zero-value Sapling output that carries the swap memo, encrypted to Maya's unified address. That output never carries funds. The amount being swapped goes in its own output in the same transaction.
