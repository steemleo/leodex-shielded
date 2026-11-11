# Security policy

This code protects real funds and real privacy. Security reports come before everything else we're working on.

## Reporting a vulnerability

**Don't open a public issue, discussion or pull request for anything exploitable.**

Report it through either:

1. **GitHub private vulnerability reporting** (preferred): the *Report a vulnerability* button on this repository's [Security tab](https://github.com/steemleo/leodex-shielded/security/advisories/new).
2. **Email** to `contact@leofinance.io` with `SECURITY` in the subject.

Include:

- the package and version;
- exact steps to reproduce;
- the impact you believe it has.

A test that reproduces it is ideal. Never test against funds or wallets that aren't yours.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | 72 hours |
| Triage and severity | 7 days |
| Fix or mitigation for anything that risks funds or keys | 14 days |
| Fix for other findings | 90 days |
| Public advisory and credit | When the fix ships, coordinated with you |

We publish a GitHub Security Advisory for any finding that affects a released version. You're credited by whatever name you choose, unless you'd rather not be.

There's no paid bounty program yet. Findings that put funds or keys at risk are rewarded at our discretion, and every valid report is credited publicly.

## Safe harbor

We won't pursue or support legal action over research done in good faith under this policy:

- no privacy violations and no service disruption;
- no access to accounts, keys or funds that aren't yours;
- a reasonable disclosure window.

If you're not sure whether something is in scope, ask first.

## Scope

**In scope: this repository.**

- **The signer:** anything that leaks key material, builds a transaction that spends or pays something the caller didn't ask for, produces a consensus-invalid transaction without refusing, or miscalculates fees or change.
- **Attestation:** any way to make `verifyEnclave` return `ok` for a report that shouldn't pass, or to get a viewing key sealed to a key that isn't bound to a verified report.
- **Sealing:** anything that weakens the HPKE seal, the request and response encryption, or the refusal of unsealed replies.
- **WASM pinning:** any way past `fetchVerifiedWasm`.
- **Supply chain:** the build, `Cargo.lock`, and the published `pkg/` files.

**Report through the same channels, but they're fixed elsewhere:**

- the shielded server and the leodex.io web app.

**Out of scope:**

- AMD SEV-SNP hardware or firmware flaws (report those to AMD), and Zcash protocol issues (report those to the Zcash developers);
- findings that need an already-compromised device or browser, or a modified build;
- dependency advisories with no reachable path in this code. Tell us anyway; we triage them as maintenance.

## Verifying what runs

- The signer files in `pkg/` are byte-identical to what leodex.io serves. [README](README.md#check-what-leodexio-serves) shows how to compare them.
- [BUILD.md](packages/leokit-shielded-sign/BUILD.md) shows how to rebuild them from source and get the same hashes.
