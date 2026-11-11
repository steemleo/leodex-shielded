/**
 * Adversarial unit tests for the SEV-SNP attestation verifier.
 *
 * We do NOT have real AMD silicon, so we build a SYNTHETIC, AMD-shaped trust
 * chain entirely from WebCrypto keys:
 *   - ARK : RSA-PSS, self-signed, CA, self-issued.
 *   - ASK : RSA-PSS, signed by ARK, CA, issuer=ARK.subject.
 *   - VCEK: EC P-384 public key, RSA-PSS-signed by ASK, end-entity,
 *           issuer=ASK.subject.
 * The synthetic SNP report is ECDSA-P384/SHA-384 signed by the VCEK's EC key
 * over report[0..0x2A0). The verifier's ARK pin is injected via the test-only
 * `_testArkSpkiPins` option so we exercise the full chain path (NOT the vcekPem
 * escape hatch) for the happy path and most reject cases.
 *
 * Each test mutates ONE thing from a known-good baseline and asserts the
 * verifier fails closed (ok=false with the expected reason).
 */
import { describe, it, expect, afterEach, beforeAll, beforeEach } from "vitest";
import { resetVcekCache, setKdsMirror, setVcekCacheStorage, verifyEnclave } from "./attestation";
import type { ShieldedClient } from "./client";

const subtle = globalThis.crypto.subtle;

// WebCrypto's lib.dom types want BufferSource backed by a plain ArrayBuffer;
// our Uint8Arrays are ArrayBufferLike. Match the source module's cast pattern.
type BS = BufferSource;
const bs = (u: Uint8Array): BS => u as unknown as BS;

// ── tiny DER encoder (just enough to forge X.509 certs) ─────────────────────
function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}
function tlv(tag: number, content: Uint8Array): Uint8Array {
  const len = derLen(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}
function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
function seq(...children: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(...children));
}
function ctx(num: number, content: Uint8Array): Uint8Array {
  return tlv(0xa0 | num, content);
}
function derInteger(n: number): Uint8Array {
  let bytes = [n & 0xff];
  if (n > 0xff) bytes = [(n >> 8) & 0xff, n & 0xff];
  // ensure positive
  if (bytes[0]! & 0x80) bytes.unshift(0x00);
  return tlv(0x02, new Uint8Array(bytes));
}
function derBool(b: boolean): Uint8Array {
  return tlv(0x01, new Uint8Array([b ? 0xff : 0x00]));
}
function derOid(dotted: string): Uint8Array {
  const parts = dotted.split(".").map(Number);
  const first = parts[0]! * 40 + parts[1]!;
  const bytes: number[] = [first];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i]!;
    const stack: number[] = [v & 0x7f];
    v >>>= 7;
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    bytes.push(...stack);
  }
  return tlv(0x06, new Uint8Array(bytes));
}
function derUtcTime(ms: number): Uint8Array {
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  const s =
    p(d.getUTCFullYear() % 100) +
    p(d.getUTCMonth() + 1) +
    p(d.getUTCDate()) +
    p(d.getUTCHours()) +
    p(d.getUTCMinutes()) +
    p(d.getUTCSeconds()) +
    "Z";
  return tlv(0x17, new TextEncoder().encode(s));
}
function derName(cn: string): Uint8Array {
  // RDNSequence: SEQUENCE OF SET OF SEQUENCE { OID(commonName 2.5.4.3), UTF8String }
  const attr = seq(derOid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)));
  return seq(tlv(0x31, attr));
}
function basicConstraintsExt(isCa: boolean): Uint8Array {
  // Extension SEQUENCE { extnID, critical TRUE, extnValue OCTET STRING(SEQUENCE{cA}) }
  const bc = seq(derBool(isCa));
  return seq(derOid("2.5.29.19"), derBool(true), tlv(0x04, bc));
}

const RSA_PSS_SHA384_ALGID = seq(derOid("1.2.840.113549.1.1.10")); // RSASSA-PSS

async function spkiOf(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await subtle.exportKey("spki", key));
}

interface KeyMeta {
  pub: CryptoKey;
  priv: CryptoKey;
  spki: Uint8Array;
}

async function genRsaPss(): Promise<KeyMeta> {
  const kp = (await subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-384",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return { pub: kp.publicKey, priv: kp.privateKey, spki: await spkiOf(kp.publicKey) };
}
async function genEcP384(): Promise<KeyMeta> {
  const kp = (await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return { pub: kp.publicKey, priv: kp.privateKey, spki: await spkiOf(kp.publicKey) };
}

async function rsaPssSign(priv: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await subtle.sign({ name: "RSA-PSS", saltLength: 48 }, priv, bs(data));
  return new Uint8Array(sig);
}

/**
 * Build a DER X.509 cert. `subjectSpki` is the SubjectPublicKeyInfo to embed;
 * `issuerPriv` is the RSA-PSS key that signs the TBS.
 */
async function makeCert(opts: {
  subjectCn: string;
  issuerCn: string;
  subjectSpki: Uint8Array;
  issuerPriv: CryptoKey;
  isCa: boolean;
  notBefore: number;
  notAfter: number;
  /** A VCEK's chip and TCB, encoded as AMD does (raw 64-byte hwID, SPLs as DER INTEGERs). */
  amd?: { chipId: Uint8Array; tcb: Tcb };
}): Promise<Uint8Array> {
  const version = ctx(0, derInteger(2)); // v3
  const serial = derInteger(1);
  const validity = seq(derUtcTime(opts.notBefore), derUtcTime(opts.notAfter));
  const amdExt = (oid: string, value: Uint8Array) => seq(derOid(oid), tlv(0x04, value));
  const amd = opts.amd
    ? [
        amdExt("1.3.6.1.4.1.3704.1.3.1", derInteger(opts.amd.tcb.bootloader)),
        amdExt("1.3.6.1.4.1.3704.1.3.2", derInteger(opts.amd.tcb.tee)),
        amdExt("1.3.6.1.4.1.3704.1.3.3", derInteger(opts.amd.tcb.snp)),
        amdExt("1.3.6.1.4.1.3704.1.3.8", derInteger(opts.amd.tcb.microcode)),
        amdExt("1.3.6.1.4.1.3704.1.4", opts.amd.chipId),
      ]
    : [];
  const extensions = ctx(3, seq(basicConstraintsExt(opts.isCa), ...amd));
  const tbs = seq(
    version,
    serial,
    RSA_PSS_SHA384_ALGID,
    derName(opts.issuerCn),
    validity,
    derName(opts.subjectCn),
    opts.subjectSpki,
    extensions,
  );
  const sig = await rsaPssSign(opts.issuerPriv, tbs);
  const sigBits = tlv(0x03, concat(new Uint8Array([0x00]), sig));
  return seq(tbs, RSA_PSS_SHA384_ALGID, sigBits);
}

function bytesToB64(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}
function derToPem(der: Uint8Array): string {
  const enc = bytesToB64(der);
  const lines = enc.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

// ── synthetic SNP report builder ────────────────────────────────────────────
const SNP_LEN = 1184;
const OFF_VERSION = 0x000;
const OFF_GUEST_POLICY = 0x008;
const OFF_VMPL = 0x030;
const OFF_REPORT_DATA = 0x050;
const OFF_MEASUREMENT = 0x090;
const OFF_REPORTED_TCB = 0x180;
const OFF_CHIP_ID = 0x1a0;
const OFF_SIGNATURE = 0x2a0;
const SIGNED_LEN = 0x2a0;

type Tcb = { bootloader: number; tee: number; snp: number; microcode: number };
/** The synthetic report's chip id (bytes 0..63) and default TCB. */
const CHIP_ID = Uint8Array.from({ length: 64 }, (_, i) => i);
const DEFAULT_TCB: Tcb = { bootloader: 5, tee: 0, snp: 20, microcode: 100 };

interface ReportFields {
  nonce: Uint8Array; // 32 bytes
  hpkePubkeyHash: Uint8Array; // 32 bytes (SHA-256 of hpke pubkey)
  measurement: Uint8Array; // 48 bytes
  policy?: bigint;
  vmpl?: number;
  tcb?: Tcb;
}

function buildUnsignedReport(f: ReportFields): Uint8Array {
  const r = new Uint8Array(SNP_LEN);
  r[OFF_VERSION] = 2;
  // guest policy: default has reserved bit17=1, SMT/DEBUG/MIGRATE off.
  const policy = f.policy ?? (1n << 17n);
  const pol = new Uint8Array(8);
  let pv = policy;
  for (let i = 0; i < 8; i++) {
    pol[i] = Number(pv & 0xffn);
    pv >>= 8n;
  }
  r.set(pol, OFF_GUEST_POLICY);
  const vmpl = f.vmpl ?? 0;
  r[OFF_VMPL] = vmpl & 0xff;
  r[OFF_VMPL + 1] = (vmpl >> 8) & 0xff;
  r.set(f.nonce, OFF_REPORT_DATA);
  r.set(f.hpkePubkeyHash, OFF_REPORT_DATA + 32);
  r.set(f.measurement, OFF_MEASUREMENT);
  const tcb = f.tcb ?? DEFAULT_TCB;
  const t = new Uint8Array(8);
  t[0] = tcb.bootloader;
  t[1] = tcb.tee;
  t[6] = tcb.snp;
  t[7] = tcb.microcode;
  r.set(t, OFF_REPORTED_TCB);
  // chip id: arbitrary fixed bytes.
  r.set(CHIP_ID, OFF_CHIP_ID);
  return r;
}

/**
 * WebCrypto ECDSA P-384 raw signature (96 bytes: R||S big-endian, 48 each) →
 * SNP's signature field: R(72-byte LE) || S(72-byte LE), low 48 bytes used.
 */
function rawSigToSnpSig(raw: Uint8Array): Uint8Array {
  const rBE = raw.subarray(0, 48);
  const sBE = raw.subarray(48, 96);
  const out = new Uint8Array(144);
  const putLE = (be: Uint8Array, base: number) => {
    for (let i = 0; i < 48; i++) out[base + i] = be[47 - i]!;
  };
  putLE(rBE, 0);
  putLE(sBE, 72);
  return out;
}

async function signReport(unsigned: Uint8Array, vcekPriv: CryptoKey): Promise<Uint8Array> {
  const signed = unsigned.subarray(0, SIGNED_LEN);
  const raw = new Uint8Array(
    await subtle.sign({ name: "ECDSA", hash: "SHA-384" }, vcekPriv, bs(signed)),
  );
  const snpSig = rawSigToSnpSig(raw);
  const out = unsigned.slice();
  out.set(snpSig, OFF_SIGNATURE);
  return out;
}

async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", bs(b)));
}
function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
function b64(b: Uint8Array): string {
  return bytesToB64(b);
}

// ── shared synthetic environment built once ─────────────────────────────────
let ark: KeyMeta, ask: KeyMeta, vcek: KeyMeta;
let arkPem: string, askPem: string, vcekDer: Uint8Array;
let arkSpkiB64: string;
let measurement: Uint8Array;
let hpkePubkey: Uint8Array, hpkeHash: Uint8Array;
const NOW = Date.UTC(2026, 0, 1); // fixed clock inside cert validity

const VALID_FROM = Date.UTC(2025, 0, 1);
const VALID_TO = Date.UTC(2030, 0, 1);

async function buildChain(opts?: {
  vcekNotBefore?: number;
  vcekNotAfter?: number;
  vcekIsCa?: boolean;
  askIsCa?: boolean;
  arkIsCa?: boolean;
  vcekIssuerCn?: string;
  vcekAmd?: { chipId: Uint8Array; tcb: Tcb };
}): Promise<{ vcekDer: Uint8Array; arkPem: string; askPem: string }> {
  const arkCert = await makeCert({
    subjectCn: "ARK-Test",
    issuerCn: "ARK-Test",
    subjectSpki: ark.spki,
    issuerPriv: ark.priv,
    isCa: opts?.arkIsCa ?? true,
    notBefore: VALID_FROM,
    notAfter: VALID_TO,
  });
  const askCert = await makeCert({
    subjectCn: "ASK-Test",
    issuerCn: "ARK-Test",
    subjectSpki: ask.spki,
    issuerPriv: ark.priv,
    isCa: opts?.askIsCa ?? true,
    notBefore: VALID_FROM,
    notAfter: VALID_TO,
  });
  const vcekCert = await makeCert({
    subjectCn: "VCEK-Test",
    issuerCn: opts?.vcekIssuerCn ?? "ASK-Test",
    subjectSpki: vcek.spki,
    issuerPriv: ask.priv,
    isCa: opts?.vcekIsCa ?? false,
    notBefore: opts?.vcekNotBefore ?? VALID_FROM,
    notAfter: opts?.vcekNotAfter ?? VALID_TO,
    amd: opts?.vcekAmd ?? { chipId: CHIP_ID, tcb: DEFAULT_TCB },
  });
  return { vcekDer: vcekCert, arkPem: derToPem(arkCert), askPem: derToPem(askCert) };
}

/**
 * A mock ShieldedClient + fetch. The fetch serves /attestation (returns the
 * given report+hpke pubkey) and the two KDS endpoints (VCEK DER + ASK,ARK PEM
 * bundle). The nonce in the URL is reflected into REPORT_DATA so the freshness
 * check passes unless we deliberately break it.
 */
function makeEnv(opts: {
  report: Uint8Array;
  hpkePubkeyB64: string;
  vcekDer: Uint8Array;
  arkPem: string;
  askPem: string;
  reflectNonce?: boolean; // re-sign report with URL nonce (default true)
  vcekPriv?: CryptoKey;
}): { client: ShieldedClient; fetch: typeof fetch } {
  const fetchFn = (async (url: string | URL): Promise<Response> => {
    const u = String(url);
    if (u.includes("/attestation")) {
      let report = opts.report;
      if ((opts.reflectNonce ?? true) && opts.vcekPriv) {
        const nonceHex = new URL(u).searchParams.get("nonce")!;
        const nonce = Uint8Array.from(
          nonceHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)),
        );
        const unsigned = opts.report.slice();
        unsigned.set(nonce, OFF_REPORT_DATA);
        report = await signReport(unsigned, opts.vcekPriv);
      }
      return new Response(
        JSON.stringify({
          mode: "snp",
          report_b64: b64(report),
          hpke_pubkey: opts.hpkePubkeyB64,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (u.includes("/cert_chain")) {
      return new Response(opts.askPem + opts.arkPem, { status: 200 });
    }
    if (u.includes("/vcek/v1/")) {
      return new Response(opts.vcekDer as unknown as BodyInit, {
        status: 200,
        headers: { "content-type": "application/octet-stream" },
      });
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;

  const client = {
    getBaseUrl: () => "https://shielded.test",
    getFetch: () => fetchFn,
  } as unknown as ShieldedClient;
  return { client, fetch: fetchFn };
}

// Every test serves its own chain for the same chip and TCB.
beforeEach(() => resetVcekCache());

beforeAll(async () => {
  ark = await genRsaPss();
  ask = await genRsaPss();
  vcek = await genEcP384();
  arkSpkiB64 = b64(ark.spki);
  measurement = new Uint8Array(48).fill(0xab);
  hpkePubkey = new Uint8Array(32).fill(0x11);
  hpkeHash = await sha256(hpkePubkey);
  const built = await buildChain();
  arkPem = built.arkPem;
  askPem = built.askPem;
  vcekDer = built.vcekDer;
});

function baseReportFields(): ReportFields {
  return {
    nonce: new Uint8Array(32), // overwritten by reflectNonce
    hpkePubkeyHash: hpkeHash,
    measurement,
  };
}

const baseOpts = () => ({
  expectedMeasurement: bytesToHex(measurement),
  productName: "Genoa" as const,
  now: NOW,
  _testArkSpkiPins: [arkSpkiB64],
});

describe("verifyEnclave — happy path", () => {
  it("valid report + chain → ok", async () => {
    const report = buildUnsignedReport(baseReportFields());
    const env = makeEnv({
      report,
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
    });
    const res = await verifyEnclave(env.client, { ...baseOpts(), fetch: env.fetch });
    expect(res.reasons).toEqual([]);
    expect(res.ok).toBe(true);
    expect(res.chainVerified).toBe(true);
    expect(res.attestedPubkey).toBe(b64(hpkePubkey));
    expect(res.measurement).toBe(bytesToHex(measurement));
    expect(res.tcb).toEqual({ bootloader: 5, tee: 0, snp: 20, microcode: 100 });
    expect(res.policy).toMatchObject({ debugAllowed: false, vmpl: 0 });
  });
});

describe("verifyEnclave — reject cases (fail closed)", () => {
  async function run(
    mutate: (f: ReportFields) => void,
    optOverrides: Record<string, unknown> = {},
    envOverrides: Partial<Parameters<typeof makeEnv>[0]> = {},
  ) {
    const f = baseReportFields();
    mutate(f);
    const report = buildUnsignedReport(f);
    const env = makeEnv({
      report,
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
      ...envOverrides,
    });
    return verifyEnclave(env.client, { ...baseOpts(), ...optOverrides, fetch: env.fetch });
  }

  it("tampered measurement → reject", async () => {
    const res = await run((f) => {
      f.measurement = new Uint8Array(48).fill(0xcd);
    });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("MEASUREMENT"))).toBe(true);
  });

  it("wrong nonce → reject", async () => {
    // disable reflectNonce so REPORT_DATA keeps zeros (won't match fresh nonce),
    // but we must still sign the report with the vcek key over the stale data.
    const f = baseReportFields();
    const unsigned = buildUnsignedReport(f);
    const signed = await signReport(unsigned, vcek.priv);
    const env = makeEnv({
      report: signed,
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      reflectNonce: false,
    });
    const res = await verifyEnclave(env.client, { ...baseOpts(), fetch: env.fetch });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.toLowerCase().includes("nonce"))).toBe(true);
  });

  it("wrong channel binding → reject", async () => {
    const res = await run((f) => {
      f.hpkePubkeyHash = new Uint8Array(32).fill(0x99); // != SHA256(hpke pubkey)
    });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("channel binding"))).toBe(true);
    expect(res.attestedPubkey).toBeUndefined();
  });

  it("bad report signature → reject", async () => {
    // sign with a DIFFERENT ec key than the VCEK cert holds.
    const rogue = await genEcP384();
    const f = baseReportFields();
    const env = makeEnv({
      report: buildUnsignedReport(f),
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      vcekPriv: rogue.priv, // mismatched signer
    });
    const res = await verifyEnclave(env.client, { ...baseOpts(), fetch: env.fetch });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("signature did not verify"))).toBe(true);
  });

  it("broken chain link (VCEK issuer != ASK subject) → reject", async () => {
    const broken = await buildChain({ vcekIssuerCn: "Evil-Intermediate" });
    const res = await run(() => {}, {}, { vcekDer: broken.vcekDer });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("VCEK.issuer != ASK.subject"))).toBe(true);
  });

  it("unpinned / mismatched ARK → reject", async () => {
    const res = await run(() => {}, { _testArkSpkiPins: [b64(ask.spki)] });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("does not match pinned"))).toBe(true);
  });

  it("no pin configured → reject", async () => {
    const res = await run(() => {}, { _testArkSpkiPins: undefined, productName: "Milan" });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("not pinned"))).toBe(true);
  });

  it("DEBUG-allowed policy → reject", async () => {
    const res = await run((f) => {
      f.policy = (1n << 17n) | (1n << 19n); // reserved + DEBUG
    });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("DEBUG"))).toBe(true);
    expect(res.policy?.debugAllowed).toBe(true);
  });

  it("MIGRATE_MA allowed (default require-disabled) → reject", async () => {
    const res = await run((f) => {
      f.policy = (1n << 17n) | (1n << 18n);
    });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("MIGRATE_MA"))).toBe(true);
  });

  it("SMT allowed + requireSmtDisabled → reject", async () => {
    const res = await run(
      (f) => {
        f.policy = (1n << 17n) | (1n << 16n);
      },
      { policy: { requireSmtDisabled: true } },
    );
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("SMT"))).toBe(true);
  });

  it("low TCB → reject", async () => {
    const res = await run(
      (f) => {
        f.tcb = { bootloader: 1, tee: 0, snp: 5, microcode: 10 };
      },
      { minTcb: { bootloader: 5, snp: 20, microcode: 100 } },
    );
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("TCB rollback"))).toBe(true);
  });

  it("TCB at or above floor → ok", async () => {
    const res = await run(() => {}, {
      minTcb: { bootloader: 5, snp: 20, microcode: 100 },
    });
    expect(res.reasons).toEqual([]);
    expect(res.ok).toBe(true);
  });

  it("expired VCEK cert → reject", async () => {
    const expired = await buildChain({
      vcekNotBefore: Date.UTC(2020, 0, 1),
      vcekNotAfter: Date.UTC(2021, 0, 1), // before NOW
    });
    const res = await run(() => {}, {}, { vcekDer: expired.vcekDer });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("VCEK certificate expired"))).toBe(true);
  });

  it("VCEK marked as CA (not end-entity) → reject", async () => {
    const bad = await buildChain({ vcekIsCa: true });
    const res = await run(() => {}, {}, { vcekDer: bad.vcekDer });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("VCEK is a CA"))).toBe(true);
  });

  it("ASK not a CA → reject", async () => {
    const bad = await buildChain({ askIsCa: false });
    const res = await run(() => {}, {}, { askPem: bad.askPem });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("ASK is not a CA"))).toBe(true);
  });

  it("wrong VMPL → reject", async () => {
    const res = await run((f) => {
      f.vmpl = 2;
    });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("VMPL"))).toBe(true);
  });

  it("expectedVmpl override accepts matching nonzero VMPL", async () => {
    const res = await run(
      (f) => {
        f.vmpl = 1;
      },
      { expectedVmpl: 1 },
    );
    expect(res.reasons).toEqual([]);
    expect(res.ok).toBe(true);
  });

  it("malformed / truncated report → reject", async () => {
    const env = makeEnv({
      report: new Uint8Array(100), // far below 1184
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      reflectNonce: false,
    });
    const res = await verifyEnclave(env.client, { ...baseOpts(), fetch: env.fetch });
    expect(res.ok).toBe(false);
    expect(res.reasons.some((r) => r.includes("report too short"))).toBe(true);
  });
});

describe("verifyEnclave — vcekPem escape hatch", () => {
  it("valid report verifies against caller VCEK without chain", async () => {
    const report = buildUnsignedReport(baseReportFields());
    const env = makeEnv({
      report,
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
    });
    const res = await verifyEnclave(env.client, {
      ...baseOpts(),
      fetch: env.fetch,
      vcekPem: derToPem(vcekDer),
    });
    expect(res.ok).toBe(true);
    expect(res.chainVerified).toBe(false);
    // the only reason present is the informational escape-hatch note.
    expect(res.reasons.length).toBe(1);
    expect(res.reasons[0]).toContain("caller-supplied VCEK");
  });
});

describe("verifyEnclave — VCEK + cert chain cache (KDS rate-limits per IP)", () => {
  /** The happy-path enclave, with every KDS request counted (and the VCEK optionally refused). */
  function countingEnv(opts: { tcb?: Tcb; vcekDer?: Uint8Array; refuseVcek?: () => boolean } = {}) {
    const env = makeEnv({
      report: buildUnsignedReport({ ...baseReportFields(), tcb: opts.tcb }),
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer: opts.vcekDer ?? vcekDer,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
    });
    const kds: string[] = [];
    const fetchFn = (async (url: string | URL) => {
      const u = String(url);
      if (u.includes("/vcek/v1/")) {
        kds.push(u);
        if (!u.includes("/cert_chain") && opts.refuseVcek?.()) {
          return new Response("Too Many Requests", { status: 429, headers: { "retry-after": "0.001" } });
        }
      }
      return env.fetch(url);
    }) as unknown as typeof fetch;
    const attest = () => verifyEnclave(env.client, { ...baseOpts(), fetch: fetchFn });
    return { attest, kds };
  }

  function memoryStorage() {
    const map = new Map<string, string>();
    return {
      map,
      getItem: (key: string) => map.get(key) ?? null,
      setItem: (key: string, value: string) => void map.set(key, value),
      removeItem: (key: string) => void map.delete(key),
    };
  }

  it("a second attestation of the same chip and TCB fetches nothing from KDS", async () => {
    const env = countingEnv();
    expect((await env.attest()).ok).toBe(true);
    expect(env.kds).toHaveLength(2);
    const again = await env.attest();
    expect(again.ok).toBe(true);
    expect(again.chainVerified).toBe(true);
    expect(env.kds).toHaveLength(2);
  });

  it("attestations running at the same time share one KDS fetch", async () => {
    const env = countingEnv();
    const results = await Promise.all([env.attest(), env.attest(), env.attest()]);
    expect(results.map((r) => r.ok)).toEqual([true, true, true]);
    expect(env.kds).toHaveLength(2);
  });

  it("verified certs persist, so a new page load attests without KDS", async () => {
    const storage = memoryStorage();
    setVcekCacheStorage(storage);
    try {
      const env = countingEnv();
      expect((await env.attest()).ok).toBe(true);
      expect([...storage.map.keys()]).toEqual([expect.stringMatching(/^leokit-shielded\.vcek\.v1\.Genoa\.[0-9a-f]{128}$/)]);
      resetVcekCache(); // the reload: memory is gone, storage stays
      const res = await env.attest();
      expect(res.ok).toBe(true);
      expect(res.chainVerified).toBe(true);
      expect(env.kds).toHaveLength(2);
    } finally {
      setVcekCacheStorage(null);
    }
  });

  const staleCopies: [string, () => Promise<Uint8Array>][] = [
    ["unparseable bytes", async () => new Uint8Array(64).fill(7)],
    [
      "an AMD-signed VCEK for another key",
      async () => {
        const other = await genEcP384();
        return makeCert({
          subjectCn: "VCEK-Test",
          issuerCn: "ASK-Test",
          subjectSpki: other.spki,
          issuerPriv: ask.priv,
          isCa: false,
          notBefore: VALID_FROM,
          notAfter: VALID_TO,
          amd: { chipId: CHIP_ID, tcb: DEFAULT_TCB },
        });
      },
    ],
  ];
  for (const [label, staleVcek] of staleCopies) {
    it(`a stored copy that no longer verifies (${label}) is dropped and fetched again`, async () => {
      const storage = memoryStorage();
      const key = `leokit-shielded.vcek.v1.Genoa.${bytesToHex(Uint8Array.from({ length: 64 }, (_, i) => i))}`;
      storage.map.set(key, JSON.stringify({ tcb: "5.0.20.100", vcek: b64(await staleVcek()), chain: askPem + arkPem }));
      setVcekCacheStorage(storage);
      try {
        const env = countingEnv();
        const res = await env.attest();
        expect(res.reasons).toEqual([]);
        expect(res.ok).toBe(true);
        expect(env.kds).toHaveLength(2);
        expect(JSON.parse(storage.map.get(key)!).vcek).toBe(b64(vcekDer));
      } finally {
        setVcekCacheStorage(null);
      }
    });
  }

  it("another TCB fetches its own VCEK", async () => {
    expect((await countingEnv().attest()).ok).toBe(true);
    const tcb = { ...DEFAULT_TCB, snp: 21 };
    const { vcekDer: vcek21 } = await buildChain({ vcekAmd: { chipId: CHIP_ID, tcb } });
    const updated = countingEnv({ tcb, vcekDer: vcek21 });
    expect((await updated.attest()).ok).toBe(true);
    expect(updated.kds.filter((u) => u.includes("snpSPL=21"))).toHaveLength(1);
  });

  it("KDS refusing the VCEK (429) fails closed after bounded retries, and the next attestation fetches again", async () => {
    let refuse = true;
    const env = countingEnv({ refuseVcek: () => refuse });
    const refused = await env.attest();
    expect(refused.ok).toBe(false);
    expect(refused.reasons.join(" ")).toMatch(/KDS VCEK fetch: HTTP 429/);
    expect(env.kds.filter((u) => !u.includes("/cert_chain"))).toHaveLength(5);
    refuse = false;
    expect((await env.attest()).ok).toBe(true);
  });
});

describe("verifyEnclave — the host's KDS mirror", () => {
  const MIRROR = "https://leodex.test/attest/kds";

  /** The happy-path enclave behind a mirror that serves good certs, is down, or serves another key's VCEK. */
  async function mirrorEnv(mirror: "good" | "down" | "other-key") {
    const env = makeEnv({
      report: buildUnsignedReport(baseReportFields()),
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
    });
    const otherVcek =
      mirror === "other-key"
        ? await makeCert({
            subjectCn: "VCEK-Test",
            issuerCn: "ASK-Test",
            subjectSpki: (await genEcP384()).spki,
            issuerPriv: ask.priv,
            isCa: false,
            notBefore: VALID_FROM,
            notAfter: VALID_TO,
            amd: { chipId: CHIP_ID, tcb: DEFAULT_TCB },
          })
        : null;
    const mirrored: string[] = [];
    const amd: string[] = [];
    const fetchFn = (async (url: string | URL) => {
      const u = String(url);
      if (u.startsWith(MIRROR)) {
        mirrored.push(u);
        if (mirror === "down") return new Response(null, { status: 503 });
        if (u.includes("/cert_chain")) return new Response(askPem + arkPem, { status: 200 });
        return new Response((otherVcek ?? vcekDer) as unknown as BodyInit, { status: 200 });
      }
      if (u.includes("/vcek/v1/")) amd.push(u);
      return env.fetch(url);
    }) as unknown as typeof fetch;
    const attest = () => verifyEnclave(env.client, { ...baseOpts(), fetch: fetchFn });
    return { attest, mirrored, amd };
  }

  beforeEach(() => setKdsMirror(MIRROR));
  afterEach(() => setKdsMirror(null));

  it("serves the certs, so AMD is not asked", async () => {
    const env = await mirrorEnv("good");
    const res = await env.attest();
    expect(res.ok).toBe(true);
    expect(res.chainVerified).toBe(true);
    expect(env.mirrored).toHaveLength(2);
    expect(env.amd).toEqual([]);
    expect(env.mirrored[0]).toMatch(/^https:\/\/leodex\.test\/attest\/kds\/vcek\/v1\/Genoa\/[0-9a-f]{128}\?blSPL=5&teeSPL=0&snpSPL=20&ucodeSPL=100$/);
  });

  it("is down: AMD is asked instead", async () => {
    const env = await mirrorEnv("down");
    expect((await env.attest()).ok).toBe(true);
    expect(env.amd).toHaveLength(2);
  });

  it("hangs: AMD is asked once the mirror's time is up", async () => {
    const env = makeEnv({
      report: buildUnsignedReport(baseReportFields()),
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
    });
    const amd: string[] = [];
    const fetchFn = (async (url: string | URL, init?: RequestInit) => {
      const u = String(url);
      if (u.startsWith(MIRROR)) {
        return new Promise<Response>((_, reject) =>
          init?.signal?.addEventListener("abort", () => reject(init.signal!.reason)),
        );
      }
      if (u.includes("/vcek/v1/")) amd.push(u);
      return env.fetch(url);
    }) as unknown as typeof fetch;
    setKdsMirror(MIRROR, 50);
    const started = Date.now();
    const res = await verifyEnclave(env.client, { ...baseOpts(), fetch: fetchFn });
    expect(res.ok).toBe(true);
    expect(amd).toHaveLength(2);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("serves a VCEK that doesn't sign this report: fetched again straight from AMD, and never kept", async () => {
    const storage = new Map<string, string>();
    setVcekCacheStorage({
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => void storage.set(key, value),
      removeItem: (key) => void storage.delete(key),
    });
    try {
      const env = await mirrorEnv("other-key");
      const res = await env.attest();
      expect(res.reasons).toEqual([]);
      expect(res.ok).toBe(true);
      expect(env.amd).toHaveLength(2);
      expect([...storage.values()].map((v) => JSON.parse(v).vcek)).toEqual([b64(vcekDer)]);
    } finally {
      setVcekCacheStorage(null);
    }
  });
});

describe("verifyEnclave — the VCEK is the one for the report's chip and TCB", () => {
  async function run(vcekAmd: { chipId: Uint8Array; tcb: Tcb }) {
    const { vcekDer: other } = await buildChain({ vcekAmd });
    const env = makeEnv({
      report: buildUnsignedReport(baseReportFields()),
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer: other,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
    });
    return verifyEnclave(env.client, { ...baseOpts(), fetch: env.fetch });
  }

  it("refuses a VCEK for another TCB, even one whose key signed the report", async () => {
    const res = await run({ chipId: CHIP_ID, tcb: { ...DEFAULT_TCB, snp: 19 } });
    expect(res.ok).toBe(false);
    expect(res.reasons.join(" ")).toMatch(/VCEK snp SPL 19 != reported 20/);
  });

  it("refuses a VCEK for another chip", async () => {
    const chipId = CHIP_ID.slice();
    chipId[0] = 0xff;
    const res = await run({ chipId, tcb: DEFAULT_TCB });
    expect(res.ok).toBe(false);
    expect(res.reasons.join(" ")).toMatch(/VCEK for another chip/);
  });

  it("a mirror can't vouch for a report claiming a newer TCB with an older TCB's VCEK", async () => {
    // The old TCB's key (leaked) signs a report claiming the new TCB. The
    // mirror serves that old VCEK; AMD serves the real one for the claimed TCB.
    const { vcekDer: oldVcek } = await buildChain({ vcekAmd: { chipId: CHIP_ID, tcb: { ...DEFAULT_TCB, snp: 19 } } });
    const newKey = await genEcP384();
    const newVcek = await makeCert({
      subjectCn: "VCEK-Test",
      issuerCn: "ASK-Test",
      subjectSpki: newKey.spki,
      issuerPriv: ask.priv,
      isCa: false,
      notBefore: VALID_FROM,
      notAfter: VALID_TO,
      amd: { chipId: CHIP_ID, tcb: DEFAULT_TCB },
    });
    const env = makeEnv({
      report: buildUnsignedReport(baseReportFields()),
      hpkePubkeyB64: b64(hpkePubkey),
      vcekDer: newVcek,
      arkPem,
      askPem,
      vcekPriv: vcek.priv,
    });
    const mirror = "https://leodex.test/attest/kds";
    const fetchFn = (async (url: string | URL) => {
      const u = String(url);
      if (u.startsWith(mirror)) {
        return u.includes("/cert_chain")
          ? new Response(askPem + arkPem, { status: 200 })
          : new Response(oldVcek as unknown as BodyInit, { status: 200 });
      }
      return env.fetch(url);
    }) as unknown as typeof fetch;
    setKdsMirror(mirror);
    try {
      const res = await verifyEnclave(env.client, { ...baseOpts(), fetch: fetchFn });
      expect(res.ok).toBe(false);
      expect(res.reasons.join(" ")).toMatch(/signature did not verify/);
    } finally {
      setKdsMirror(null);
    }
  });
});
