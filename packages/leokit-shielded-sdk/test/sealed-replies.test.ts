import { beforeAll, describe, expect, it, vi } from "vitest";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ShieldedClient } from "../src/client";
import { ShieldedReplyIntegrityError } from "../src/types";

/**
 * TLS for the shielded server ends before the enclave, so the
 * only replies the client may read are the ones the attested enclave sealed
 * under this request's HPKE exporter key. A plaintext reply (e.g. a swapped
 * /wallet/address) or a sealed one changed or replayed on the way is refused.
 * The fake enclave below opens the client's real envelope, as the server does.
 */

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
const utf8 = (s: string) => new TextEncoder().encode(s);
const INFO = utf8("leokit-shielded/ufvk/v1");
const AAD = utf8("ufvk");
const RESPONSE_CTX = utf8("leokit-shielded/response/v1");
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const buf = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

let enclaveKeys: CryptoKeyPair;
let attestedPubkey: string;
beforeAll(async () => {
  enclaveKeys = await suite.kem.generateKeyPair();
  attestedPubkey = b64(new Uint8Array(await suite.kem.serializePublicKey(enclaveKeys.publicKey)));
});

/** What the enclave does with a sealed request: open the UFVK, derive this request's response key. */
async function openRequest(body: { ufvk_enc: string }) {
  const blob = new Uint8Array(Buffer.from(body.ufvk_enc, "base64"));
  const recipient = await suite.createRecipientContext({ recipientKey: enclaveKeys.privateKey, enc: buf(blob.subarray(0, 32)), info: INFO });
  const ufvk = new TextDecoder().decode(await recipient.open(buf(blob.subarray(32)), AAD));
  const responseKey = new Uint8Array(await recipient.export(buf(RESPONSE_CTX), 32));
  return { ufvk, responseKey };
}

function seal(key: Uint8Array, value: unknown) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = chacha20poly1305(key, nonce).encrypt(utf8(JSON.stringify(value)));
  return { enc: b64(new Uint8Array([...nonce, ...ct])) };
}

function client(reply: (body: { ufvk_enc: string }) => unknown) {
  const calls: string[] = [];
  const fetchFn = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? "GET"} ${new URL(url).pathname}`);
    const out = await reply(JSON.parse(String(init?.body)));
    return new Response(JSON.stringify(out), { status: 200, headers: { "content-type": "application/json" } });
  });
  const c = new ShieldedClient({ baseUrl: "https://shielded.test", fetch: fetchFn as never, expectedMeasurement: ["ab".repeat(48)] });
  // Attestation itself is covered in attestation.test.ts; start from its result.
  (c as unknown as { attestedPubkey: string }).attestedPubkey = attestedPubkey;
  return { c, calls };
}

const ADDRESS = { unified_address: "u1mine", receivers: { sapling: true, orchard: false, transparent: true } };

describe("replies to sealed requests", () => {
  it("opens the reply the enclave sealed for this request", async () => {
    const { c, calls } = client(async body => {
      const { ufvk, responseKey } = await openRequest(body as { ufvk_enc: string });
      expect(ufvk).toBe("uview1me");
      return seal(responseKey, ADDRESS);
    });
    await expect(c.walletAddress("uview1me")).resolves.toEqual(ADDRESS);
    expect(calls).toEqual(["POST /wallet/address"]);
  });

  it("refuses a forged plaintext address, once, with no unsealed retry", async () => {
    const { c, calls } = client(() => ({ unified_address: "u1attacker", receivers: ADDRESS.receivers }));
    const err = await c.walletAddress("uview1me").catch(e => e);
    expect(err).toBeInstanceOf(ShieldedReplyIntegrityError);
    expect(err).toMatchObject({ code: "SHIELDED_REPLY_UNVERIFIED", reason: "unsealed", path: "/wallet/address" });
    expect(calls).toEqual(["POST /wallet/address"]);
  });

  it("refuses a sealed reply changed on the way", async () => {
    const { c } = client(async body => {
      const { responseKey } = await openRequest(body as { ufvk_enc: string });
      const sealed = Buffer.from(seal(responseKey, ADDRESS).enc, "base64");
      sealed[sealed.length - 1] ^= 0x01;
      return { enc: sealed.toString("base64") };
    });
    await expect(c.walletAddress("uview1me")).rejects.toMatchObject({ reason: "unopenable", path: "/wallet/address" });
  });

  it("refuses a reply sealed for another request", async () => {
    const { c } = client(() => seal(crypto.getRandomValues(new Uint8Array(32)), { ...ADDRESS, unified_address: "u1attacker" }));
    await expect(c.walletAddress("uview1me")).rejects.toMatchObject({ reason: "unopenable" });
  });

  it("treats plaintext /scanner/delta and /scanner/scan replies as errors, not data", async () => {
    const { c, calls } = client(() => ({ notes: [], received_zat: 999_000_000, tip_height: 3_100_000 }));
    await expect(c.scannerDelta({ ufvk: "uview1me", fromHeight: 3_000_000 })).rejects.toMatchObject({ reason: "unsealed", path: "/scanner/delta" });
    await expect(c.scannerScan({ ufvk: "uview1me", birthdayHeight: 3_000_000 })).rejects.toMatchObject({ reason: "unsealed", path: "/scanner/scan" });
    expect(calls).toEqual(["POST /scanner/delta", "POST /scanner/scan"]);
  });

  it("still opens a sealed /scanner/delta reply", async () => {
    const outcome = { notes: [], received_zat: 0, from_height: 3_000_000, to_height: 3_000_010 };
    const { c } = client(async body => seal((await openRequest(body as { ufvk_enc: string })).responseKey, outcome));
    await expect(c.scannerDelta({ ufvk: "uview1me", fromHeight: 3_000_000 })).resolves.toEqual(outcome);
  });
});
