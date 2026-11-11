/**
 * Client-side HPKE seal for the viewing key (UFVK), matching the server:
 *   Suite: HPKE-base / DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
 *          ChaCha20Poly1305
 *   info:  "leokit-shielded/ufvk/v1"
 *   aad:   "ufvk"
 *   Wire:  base64( enc(32B) || ciphertext+tag )
 *
 * Everything between the browser and the enclave sees only the sealed
 * envelope. ShieldedClient seals to the key bound into the attestation
 * report (`sealUfvkToKey`). `sealUfvk`, which fetches the server's key
 * without attesting, is the development path only.
 */
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

const INFO_BYTES = new TextEncoder().encode("leokit-shielded/ufvk/v1");
const AAD_BYTES = new TextEncoder().encode("ufvk");

/**
 * RFC 9180 exporter context for the per-request response-encryption key — must
 * byte-match the server's RESPONSE_EXPORT_CONTEXT. Derived from the same HPKE
 * context as the sealed UFVK, so client and enclave share the key with no extra
 * round-trip; the response is encrypted end to end (proxies on the way see only
 * ciphertext).
 */
const RESPONSE_EXPORT_CTX: ArrayBuffer = (() => {
  const u = new TextEncoder().encode("leokit-shielded/response/v1");
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
})();

/**
 * RFC 9180 exporter context for the per-request REQUEST-encryption key — a
 * SEPARATE context from the response one, must byte-match the server's
 * REQUEST_EXPORT_CONTEXT. Lets the client encrypt sensitive request fields
 * (e.g. `known_nullifiers`) so nothing on the way can see which notes the user
 * tracks. Derived from the same HPKE context as the sealed UFVK — no extra
 * round-trip.
 */
const REQUEST_EXPORT_CTX: ArrayBuffer = (() => {
  const u = new TextEncoder().encode("leokit-shielded/request/v1");
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
})();

export interface SealedUfvk {
  /** base64( enc ‖ ciphertext+tag ) to send as `ufvk_enc`. */
  envelope: string;
  /** Per-request HPKE exporter key (32 B) for sensitive REQUEST fields — pass to {@link encryptRequest}. */
  requestKey: Uint8Array;
  /** Per-request HPKE exporter key (32 B) — pass to {@link decryptResponse}. */
  responseKey: Uint8Array;
}

const cachedPubkey = new Map<string, CryptoKey>();

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

function base64Decode(s: string): Uint8Array {
  const bin = atob(s.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64Encode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i] as number);
  }
  return btoa(bin);
}

function concatU8(a: ArrayBuffer | Uint8Array, b: ArrayBuffer | Uint8Array): Uint8Array {
  const aa = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
  const out = new Uint8Array(aa.length + bb.length);
  out.set(aa, 0);
  out.set(bb, aa.length);
  return out;
}

async function fetchServerPubkey(baseUrl: string): Promise<CryptoKey> {
  const base = baseUrl.replace(/\/+$/, "");
  const hit = cachedPubkey.get(base);
  if (hit) return hit;

  const r = await fetch(`${base}/crypto/pubkey`, { method: "GET" });
  if (!r.ok) throw new Error(`/crypto/pubkey: HTTP ${r.status}`);
  const j = (await r.json()) as { public_key: string; suite: string };
  // Sanity: server suite string is informational; we don't reject on it
  // (the suite is pinned in the CipherSuite construction above) but if
  // the server ever rotates we'll fail closed on decrypt.
  const raw = base64Decode(j.public_key);
  // importKey wants a real ArrayBuffer; slice the Uint8Array's underlying
  // buffer so we hand over exactly the 32-byte X25519 key, not whatever
  // slice the Uint8Array might be viewing.
  const rawBuffer = raw.buffer.slice(
    raw.byteOffset,
    raw.byteOffset + raw.byteLength,
  ) as ArrayBuffer;
  const key = await suite.kem.importKey("raw", rawBuffer, true);
  cachedPubkey.set(base, key);
  return key;
}

/**
 * HPKE-seal a UFVK to the server's X25519 public key. Returns the
 * base64 envelope to pass as `ufvk_enc` on /scanner/delta or
 * /wallet/address.
 *
 * Fetches + caches the server pubkey on first call. Re-throws on
 * any network or KEM error so the caller can surface a clear message.
 */
export async function sealUfvk(baseUrl: string, ufvk: string): Promise<SealedUfvk> {
  const recipientPublicKey = await fetchServerPubkey(baseUrl);
  const sender = await suite.createSenderContext({
    recipientPublicKey,
    info: INFO_BYTES,
  });
  const ct = await sender.seal(new TextEncoder().encode(ufvk), AAD_BYTES);
  // `sender.enc` is the X25519 encapsulated key (32 bytes). Server expects
  // base64( enc || ciphertext+tag ). The exporter keys encrypt the request
  // (sensitive fields) and decrypt the response.
  const requestKey = new Uint8Array(await sender.export(REQUEST_EXPORT_CTX, 32));
  const responseKey = new Uint8Array(await sender.export(RESPONSE_EXPORT_CTX, 32));
  return { envelope: base64Encode(concatU8(sender.enc, ct)), requestKey, responseKey };
}

/**
 * HPKE-seal a UFVK to a SPECIFIC X25519 public key (base64) — the one the
 * client has just ATTESTED (verifyEnclave returns it as `attestedPubkey`).
 * Unlike {@link sealUfvk} this does NOT fetch /crypto/pubkey, so the key the
 * UFVK is encrypted to is the measurement-bound, attested key and nothing the
 * server can swap at request time. This is the secure path.
 */
export async function sealUfvkToKey(pubkeyB64: string, ufvk: string): Promise<SealedUfvk> {
  const raw = base64Decode(pubkeyB64);
  const rawBuffer = raw.buffer.slice(
    raw.byteOffset,
    raw.byteOffset + raw.byteLength,
  ) as ArrayBuffer;
  const recipientPublicKey = await suite.kem.importKey("raw", rawBuffer, true);
  const sender = await suite.createSenderContext({ recipientPublicKey, info: INFO_BYTES });
  const ct = await sender.seal(new TextEncoder().encode(ufvk), AAD_BYTES);
  const requestKey = new Uint8Array(await sender.export(REQUEST_EXPORT_CTX, 32));
  const responseKey = new Uint8Array(await sender.export(RESPONSE_EXPORT_CTX, 32));
  return { envelope: base64Encode(concatU8(sender.enc, ct)), requestKey, responseKey };
}

/**
 * Decrypt a server response sealed with the per-request HPKE exporter key.
 * Input is base64(nonce(12) ‖ ChaCha20Poly1305 ciphertext+tag); returns the
 * plaintext JSON string. The enclave encrypted it; nothing on the way saw it.
 */
export function decryptResponse(responseKey: Uint8Array, b64: string): string {
  const blob = base64Decode(b64);
  const nonce = blob.subarray(0, 12);
  const ct = blob.subarray(12);
  const pt = chacha20poly1305(responseKey, nonce).decrypt(ct);
  return new TextDecoder().decode(pt);
}

/**
 * Encrypt sensitive REQUEST bytes with the per-request HPKE exporter key
 * (ChaCha20Poly1305, random 96-bit nonce). Mirrors the server's
 * `e2e::seal_response` wire format; the server decrypts with `e2e::open_sealed`
 * using the identical exporter key (REQUEST_EXPORT_CTX). Returns
 * base64(nonce(12) ‖ ciphertext+tag) to send as `enc_req`. Anything on the way
 * sees only ciphertext, so it can't tell which notes (nullifiers) the user tracks.
 */
export function encryptRequest(requestKey: Uint8Array, plaintext: Uint8Array): string {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = chacha20poly1305(requestKey, nonce).encrypt(plaintext);
  return base64Encode(concatU8(nonce, ct));
}

/**
 * Drop the cached pubkey for a given server. Tests + dev helper —
 * production code shouldn't need this; pubkey rotation will trigger
 * a decrypt failure that surfaces as a backend error and the cache
 * can stay until the next page load.
 */
export function resetServerPubkeyCache(baseUrl?: string): void {
  if (!baseUrl) {
    cachedPubkey.clear();
    return;
  }
  cachedPubkey.delete(baseUrl.replace(/\/+$/, ""));
}
