# Attestation: what the SDK checks before it sends your viewing key

`verifyEnclave` in [`attestation.ts`](../packages/leokit-shielded-sdk/src/attestation.ts) does the checking. `ShieldedClient` calls it before the first viewing key is sealed and caches the result for the session. If any check fails, the client throws `ShieldedAttestationError` with the reasons, and nothing is sent.

It runs in the browser on WebCrypto. The ASN.1 and X.509 parsing is written by hand, so the SDK carries no certificate library. That parser is the part we most want reviewed.

## The checks

Every check below records a reason on failure. `ok` is true only when there are no reasons and the server's HPKE key is bound to the report.

Two options exist for offline use and tests, and `ShieldedClient` sets neither: `vcekPem` verifies the report against a supplied VCEK and skips checks 6–10, and `_testArkSpkiPins` replaces the pinned root.

| # | Check | Why it matters |
| --- | --- | --- |
| 1 | **Fresh nonce.** `REPORT_DATA[0..32]` equals 32 random bytes the client made for this request | An old report can't be replayed |
| 2 | **Report format.** At least 1,184 bytes, version 2 or later | Rejects truncated reports before parsing further. A version below 2 is recorded as a failure |
| 3 | **Measurement.** `MEASUREMENT` equals one of the expected launch measurements (SHA-384, 48 bytes) | Proves which image the VM booted. A list is accepted so an image can rotate: ship `[current, next]`, swap, then drop the old value |
| 4 | **Key binding.** `REPORT_DATA[32..64]` equals SHA-256 of the HPKE public key the server returned | Stops a relay from pairing a genuine report with its own key. The client seals only to this key |
| 5 | **Report signature.** ECDSA P-384 over SHA-384 of `report[0..0x2A0)`, verified with the VCEK's public key | Proves the AMD secure processor produced the report, not the host |
| 6 | **Certificate chain.** VCEK ← ASK ← ARK, each link RSASSA-PSS with SHA-384, and the ARK self-signed | Links the VCEK to AMD's root |
| 7 | **Pinned root.** The ARK's public key must byte-match the AMD Genoa root embedded in the SDK | The SDK never trusts a root the server or a key server hands it. This pin is the trust anchor. Milan has no pin, so Milan reports always fail |
| 8 | **Chain sanity.** ARK and ASK are CAs, the VCEK isn't, and each issuer matches the subject above it | Catches a well-signed certificate placed in the wrong position |
| 9 | **Validity dates.** Every certificate's `notBefore`/`notAfter` window contains the current time | Rejects expired or not-yet-valid certificates |
| 10 | **VCEK binding.** The VCEK's hardware-ID extension equals the report's `CHIP_ID`, and its SPL extensions equal the report's `REPORTED_TCB` | A genuine VCEK for another chip, or for an older and vulnerable firmware level, can't sign for this report |
| 11 | **TCB floor** (optional). Each `REPORTED_TCB` component is at or above a configured minimum | Blocks a host that rolled back to firmware with known bugs. leodex.io sets a floor |
| 12 | **Guest policy.** DEBUG must be off, always. MIGRATE_MA must be off by default. SMT can be required off | A debuggable guest has no memory protection. A migratable guest's secrets can be moved by the host |
| 13 | **Privilege level.** The report's VMPL is 0 by default | A report from a less-privileged part of the guest proves less |

## Where the certificates come from

The VCEK is specific to the chip and its firmware level, so the client looks it up for each report:

1. **Memory, then storage.** The app can supply storage through `setVcekCacheStorage` (leodex.io uses `localStorage`, except in incognito mode). One entry per chip, tagged with its firmware level. A new level replaces it.
2. **A mirror on the web app's own origin, if configured.** `setKdsMirror("/attest/kds")`. leodex.io uses one because AMD's key server rate-limits by IP.
3. **AMD's Key Distribution Service** at `kdsintf.amd.com`. It retries on HTTP 429 and 5xx with backoff, up to four times.

None of these sources is trusted. Certificates from any of them go through checks 6–10. A cached or mirrored copy that fails is thrown away and fetched again straight from AMD. A mirror that hasn't answered within 6 seconds is skipped. Only certificates that verified are saved to storage. The worst a bad source can do is cause a failed attestation, never a passing one.

After a failed attestation, the client refuses to seal for 60 seconds (`attestRetryAfterMs`) instead of hammering AMD's key server.

## What it does not check

- **Certificate revocation.** The client doesn't fetch AMD's revocation lists. The VCEK binding (check 10) and the TCB floor (check 11) cover the case that matters most: a key from an older firmware level.
- **Full RFC 5280 path validation.** Check 8 covers what matters for this fixed three-certificate chain. Name constraints and policy extensions aren't evaluated.
- **The image itself.** Attestation proves the server booted the image with the measurement we pinned. It can't show what that image does. The enclave image isn't published yet, so you can't reproduce the measurement yourself.

## What leodex.io pins today

These values are in the site's public JavaScript bundle. They change with each enclave image or firmware floor, so check the live bundle for the current ones. The site may pin more than one measurement during a rotation.

| Setting | Value (November 2026) |
| --- | --- |
| Launch measurement | `8eec9baf8a45277c6ac379f3483897e4c9bd51b8188c2d30e85fb2b9ef0122dd1467f1ab4b436b4f85975c5066d0ea47` |
| Silicon family | Genoa |
| TCB floor | bootloader 9, TEE 0, SNP 23, microcode 72 |
| Certificate mirror | `/attest/kds` on leodex.io, then `kdsintf.amd.com` |

To check the live server against these values, call `GET https://shielded.leokit.dev/attestation?nonce=<64 hex chars>` and read `MEASUREMENT` (offset `0x90`, 48 bytes) and `REPORTED_TCB` (offset `0x180`) from the base64 report. The offsets are in AMD's SEV-SNP ABI specification (document 56860).

## Running without attestation

If a `ShieldedClient` has no expected measurement (neither in its options nor through `setTrustedMeasurement`), it logs a warning and seals to an unattested key. That mode exists for local development against a server that can't attest. Never ship it. leodex.io's release checks fail if that development switch reaches a build.

## Using it directly

```ts
import { verifyEnclave, ShieldedClient } from "leokit-shielded-sdk";

const client = new ShieldedClient({ baseUrl: "https://shielded.leokit.dev" });
const result = await verifyEnclave(client, {
  expectedMeasurement: ["<96 hex chars>"],
  productName: "Genoa",
  minTcb: { bootloader: 9, tee: 0, snp: 23, microcode: 72 },
});

if (!result.ok) throw new Error(result.reasons.join("; "));
// result.attestedPubkey is the only key a viewing key may be sealed to.
// result.tcb and result.policy are returned on failure too, once the report has parsed.
```

