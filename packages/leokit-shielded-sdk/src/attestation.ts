/**
 * Client-side AMD SEV-SNP attestation of the shielded server.
 *
 * The server exposes `GET /attestation?nonce=<hex>`, which returns a hardware
 * attestation report (base64, 1184+ bytes) and the server's HPKE public key.
 * `verifyEnclave` checks, before any viewing key is sealed:
 *
 *   - freshness: REPORT_DATA[0..32] equals the client's random nonce;
 *   - identity: MEASUREMENT equals one of the expected launch measurements;
 *   - key binding: REPORT_DATA[32..64] equals SHA-256 of the HPKE public key;
 *   - authenticity: the report's ECDSA P-384 signature verifies against the
 *     VCEK, the VCEK -> ASK -> ARK chain verifies (RSASSA-PSS, SHA-384), and
 *     the ARK's public key byte-matches the AMD root pinned below;
 *   - chain sanity and validity dates for every certificate;
 *   - the VCEK is the one for this report's CHIP_ID and REPORTED_TCB;
 *   - an optional TCB floor, the guest policy (DEBUG always rejected,
 *     MIGRATE_MA rejected by default, SMT optional) and VMPL (0 by default).
 *
 * `ok` is true only when every check passes and the key binding holds. Each
 * failure adds a line to `reasons`.
 *
 * Not checked: certificate revocation lists, and full RFC 5280 path
 * validation beyond the sanity checks above. See docs/attestation.md.
 *
 * `opts.vcekPem` verifies the report signature against a caller-supplied VCEK
 * and skips the chain (`chainVerified` is false). It exists for offline use and
 * tests; the default path fetches and verifies the full chain.
 */
import type { ShieldedClient } from "./client";

// ── SNP attestation report ABI offsets (AMD spec 56860, report v2) ──────────
const SNP_REPORT_MIN_LEN = 1184;
const OFF_VERSION = 0x000;
const OFF_GUEST_POLICY = 0x008; // 8 bytes, little-endian GuestPolicy
const OFF_VMPL = 0x030; // 4 bytes, little-endian (privilege level of the report)
const OFF_REPORT_DATA = 0x050; // 64 bytes
const OFF_MEASUREMENT = 0x090; // 48 bytes
const OFF_REPORTED_TCB = 0x180; // 8 bytes, little-endian TcbVersion
const OFF_CHIP_ID = 0x1a0; // 64 bytes
const OFF_SIGNATURE = 0x2a0; // ECDSA: R(72 LE) || S(72 LE), 48 used each
const SIGNED_LEN = 0x2a0; // signature covers report[0..0x2A0)

// ── GuestPolicy bit layout (AMD spec 56860, GUEST_POLICY) ───────────────────
// bits 0..7 ABI_MINOR, 8..15 ABI_MAJOR, 16 SMT, 17 reserved(=1), 18 MIGRATE_MA,
// 19 DEBUG, 20 SINGLE_SOCKET, ...  DEBUG=1 lets the host attach a debugger to
// the guest, which voids SEV-SNP memory confidentiality/integrity entirely.
const POLICY_BIT_SMT = 16n;
const POLICY_BIT_MIGRATE_MA = 18n;
const POLICY_BIT_DEBUG = 19n;

const KDS_BASE = "https://kdsintf.amd.com";

export interface VerifyEnclaveOptions {
  /**
   * Expected launch measurement, 48-byte SHA-384 as hex (96 hex chars). A
   * list accepts any of its entries — used while an enclave image rotates
   * (ship [current, next] before the swap, drop the old one after).
   */
  expectedMeasurement: string | readonly string[];
  /**
   * Silicon family for KDS lookups + the pinned ARK. Defaults to "Genoa".
   * "Milan" is accepted, but no Milan root is pinned, so it fails closed.
   */
  productName?: "Genoa" | "Milan";
  /**
   * Optional override for the fetch implementation (tests / non-browser).
   * Defaults to the client's configured fetch.
   */
  fetch?: typeof fetch;
  /**
   * ESCAPE HATCH (offline / tests): a PEM- or DER-encoded VCEK certificate to
   * verify the report signature against, SKIPPING the KDS fetch + chain. When
   * set, `chainVerified` will be false and `ok` requires nonce + measurement +
   * report-signature only.
   */
  vcekPem?: string;
  /**
   * TCB ROLLBACK FLOOR. Reject the report if any present REPORTED_TCB component
   * is BELOW the configured minimum. This blocks an attacker (or a host that
   * "downgraded" the platform) from presenting a report produced by firmware
   * with a known vulnerability. Defaults to undefined → accept any TCB, but the
   * parsed TCB is ALWAYS returned in the result so callers can enforce a floor
   * out-of-band. Set the components you have a published baseline for.
   */
  minTcb?: { bootloader?: number; tee?: number; snp?: number; microcode?: number };
  /**
   * Guest-policy assertions. DEBUG is ALWAYS rejected (a debug-enabled guest
   * has no SEV-SNP protection); this is not configurable. SMT / MIGRATE_MA are
   * asserted only when set here:
   *  - requireSmtDisabled: reject if the policy permits SMT (sibling-thread
   *    side-channel exposure). Default false (do not assert).
   *  - requireMigrateMaDisabled: reject if the policy permits migration-agent
   *    association. Default true (a migratable guest can have its secrets moved
   *    by the host). Set false to allow.
   */
  policy?: { requireSmtDisabled?: boolean; requireMigrateMaDisabled?: boolean };
  /**
   * Expected VMPL of the report (REPORT's VMPL field). Defaults to 0 — the
   * attesting service must run at the highest guest privilege level. A report
   * minted at a lower VMPL could have been produced by less-trusted guest code.
   */
  expectedVmpl?: number;
  /**
   * Trusted wall-clock for certificate validity checks, ms since epoch.
   * Defaults to Date.now(). Certs whose validity window does not contain this
   * instant are rejected on the KDS chain path.
   */
  now?: number;
  /**
   * TEST-ONLY override for the pinned-ARK trust anchor. When provided, these
   * base64(DER SubjectPublicKeyInfo) values REPLACE the built-in pins for the
   * product during pinning. Intended for unit tests that build a synthetic
   * AMD-style chain; production callers MUST NOT set this (it would let a
   * caller substitute the root of trust).
   */
  _testArkSpkiPins?: string[];
}

/** Parsed REPORTED_TCB component versions (SPL), exposed in the result. */
export interface TcbVersions {
  bootloader: number;
  tee: number;
  snp: number;
  microcode: number;
}

/** Parsed GuestPolicy flags + the report's VMPL, exposed in the result. */
export interface PolicyInfo {
  debugAllowed: boolean;
  smtAllowed: boolean;
  migrateMaAllowed: boolean;
  vmpl: number;
}

export interface VerifyEnclaveResult {
  /** True iff nonce + measurement + report-sig (+ chain, unless vcekPem) pass. */
  ok: boolean;
  /** MEASUREMENT field from the report, hex (lowercase). Empty on parse failure. */
  measurement: string;
  /** Human-readable failure reasons; empty when ok. */
  reasons: string[];
  /** Attestation mode reported by the server ("snp" | "pre-tee" | ...). */
  mode?: string;
  /** True iff the full VCEK→ASK→ARK chain was fetched + verified against the pinned ARK. */
  chainVerified: boolean;
  /**
   * The enclave's HPKE public key (base64), present ONLY when channel binding
   * verified (REPORT_DATA[32..64] == SHA256 of this key). Callers MUST encrypt
   * the UFVK to THIS key and no other — it is the attested secure-channel key.
   */
  attestedPubkey?: string;
  /**
   * Parsed REPORTED_TCB component versions from the report. Always present once
   * the report parsed (even when ok is false), so callers can enforce a TCB
   * floor out-of-band or log the platform firmware level.
   */
  tcb?: TcbVersions;
  /**
   * Parsed GuestPolicy flags + report VMPL. Always present once the report
   * parsed, so callers can audit the enclave's launch policy.
   */
  policy?: PolicyInfo;
}

// ── small helpers ───────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const h = hex.trim().toLowerCase().replace(/^0x/, "");
  if (h.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) throw new Error("invalid hex");
    out[i] = b;
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
  return s;
}

function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(b: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]!);
  return btoa(bin);
}

/** Constant-time-ish equality (length + value). Not security-critical here. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Convert a 72-byte little-endian SNP signature scalar to a 48-byte
 * big-endian P-384 scalar. The SNP report stores R and S as little-endian
 * fixed-width 72-byte fields; only the low 48 bytes are meaningful for P-384.
 */
function snpScalarToBE(le72: Uint8Array): Uint8Array {
  // take low 48 bytes (the rest must be zero for a valid P-384 scalar), reverse
  const le = le72.subarray(0, 48);
  const be = new Uint8Array(48);
  for (let i = 0; i < 48; i++) be[i] = le[47 - i]!;
  return be;
}

// ── reported-TCB → KDS SPL query params ─────────────────────────────────────
// TcbVersion is 8 little-endian bytes: [bootloader, tee, rsvd, rsvd, rsvd, rsvd,
// snp, microcode]. KDS wants the SPL values for each component.
interface ReportedTcb {
  bootloader: number;
  tee: number;
  snp: number;
  microcode: number;
}
function parseReportedTcb(report: Uint8Array): ReportedTcb {
  const t = report.subarray(OFF_REPORTED_TCB, OFF_REPORTED_TCB + 8);
  return {
    bootloader: t[0]!,
    tee: t[1]!,
    snp: t[6]!,
    microcode: t[7]!,
  };
}

// ── GuestPolicy + VMPL parsing ──────────────────────────────────────────────
/** Read GUEST_POLICY (8 LE bytes at 0x08) as a BigInt and decode the flags. */
function parsePolicyInfo(report: Uint8Array): PolicyInfo {
  let policy = 0n;
  const p = report.subarray(OFF_GUEST_POLICY, OFF_GUEST_POLICY + 8);
  for (let i = 7; i >= 0; i--) policy = (policy << 8n) | BigInt(p[i]!);
  const bit = (n: bigint): boolean => ((policy >> n) & 1n) === 1n;
  // VMPL is a 4-byte LE field.
  const v = report.subarray(OFF_VMPL, OFF_VMPL + 4);
  const vmpl = v[0]! | (v[1]! << 8) | (v[2]! << 16) | (v[3]! << 24);
  return {
    debugAllowed: bit(POLICY_BIT_DEBUG),
    smtAllowed: bit(POLICY_BIT_SMT),
    migrateMaAllowed: bit(POLICY_BIT_MIGRATE_MA),
    vmpl: vmpl >>> 0,
  };
}

// ── minimal ASN.1 DER reader (just enough for X.509 EC certs) ────────────────
interface Asn1 {
  tag: number;
  /** content bytes (not including tag/length header). */
  content: Uint8Array;
  /** full element bytes including header (for TBS extraction). */
  full: Uint8Array;
  /** offset just past this element in the parent buffer. */
  end: number;
}

function readTLV(buf: Uint8Array, offset: number): Asn1 {
  const start = offset;
  const tag = buf[offset]!;
  offset += 1;
  let len = buf[offset]!;
  offset += 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("unsupported DER length");
    len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | buf[offset]!;
      offset += 1;
    }
  }
  const content = buf.subarray(offset, offset + len);
  const end = offset + len;
  return { tag, content, full: buf.subarray(start, end), end };
}

/** Iterate the children of a SEQUENCE/SET content buffer. */
function children(content: Uint8Array): Asn1[] {
  const out: Asn1[] = [];
  let off = 0;
  while (off < content.length) {
    const el = readTLV(content, off);
    out.push(el);
    off = el.end;
  }
  return out;
}

// ── algorithm OIDs (dotted-decimal) we need to distinguish ───────────────────
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"; // rsaEncryption
const OID_RSASSA_PSS = "1.2.840.113549.1.1.10"; // RSASSA-PSS
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"; // id-ecPublicKey
const OID_BASIC_CONSTRAINTS = "2.5.29.19"; // id-ce-basicConstraints
// AMD VCEK extensions (spec 57230): the chip and TCB the VCEK was derived for.
const OID_AMD_HWID = "1.3.6.1.4.1.3704.1.4";
const OID_AMD_SPL: Record<keyof ReportedTcb, string> = {
  bootloader: "1.3.6.1.4.1.3704.1.3.1",
  tee: "1.3.6.1.4.1.3704.1.3.2",
  snp: "1.3.6.1.4.1.3704.1.3.3",
  microcode: "1.3.6.1.4.1.3704.1.3.8",
};

/** Decode an ASN.1 OBJECT IDENTIFIER content (sans tag/len) to dotted-decimal. */
function decodeOid(content: Uint8Array): string {
  if (content.length === 0) return "";
  const parts: number[] = [];
  const first = content[0]!;
  parts.push(Math.floor(first / 40), first % 40);
  let val = 0;
  for (let i = 1; i < content.length; i++) {
    const b = content[i]!;
    val = (val << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join(".");
}

// ── ASN.1 time parsing (UTCTime / GeneralizedTime) → ms since epoch ─────────
/**
 * Decode an X.509 validity time. UTCTime (tag 0x17) is "YYMMDDHHMMSSZ" (2-digit
 * year, RFC5280 pivot: 00..49 → 20xx, 50..99 → 19xx). GeneralizedTime (tag
 * 0x18) is "YYYYMMDDHHMMSSZ". We require the trailing 'Z' (UTC) — AMD certs use
 * it — and reject anything we cannot parse so a malformed date FAILS CLOSED.
 */
function parseAsn1Time(el: Asn1): number {
  const s = new TextDecoder("ascii").decode(el.content).trim();
  let year: number, mo: number, d: number, h: number, mi: number, sec: number, rest: string;
  if (el.tag === 0x17) {
    // UTCTime: YYMMDDHHMMSSZ
    if (!/^\d{12}Z$/.test(s)) throw new Error(`bad UTCTime "${s}"`);
    const yy = Number(s.slice(0, 2));
    year = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = s.slice(2);
  } else if (el.tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    if (!/^\d{14}Z$/.test(s)) throw new Error(`bad GeneralizedTime "${s}"`);
    year = Number(s.slice(0, 4));
    rest = s.slice(4);
  } else {
    throw new Error(`unsupported time tag 0x${el.tag.toString(16)}`);
  }
  mo = Number(rest.slice(0, 2));
  d = Number(rest.slice(2, 4));
  h = Number(rest.slice(4, 6));
  mi = Number(rest.slice(6, 8));
  sec = Number(rest.slice(8, 10));
  const ms = Date.UTC(year, mo - 1, d, h, mi, sec);
  if (Number.isNaN(ms)) throw new Error(`unparseable time "${s}"`);
  return ms;
}

interface ParsedCert {
  /** raw TBSCertificate bytes (DER, including the SEQUENCE header) — the signed data. */
  tbs: Uint8Array;
  /** validity notBefore / notAfter, ms since epoch (parsed from TBS). */
  notBefore: number;
  notAfter: number;
  /** raw DER of the issuer Name (for issuer/subject linkage by byte-equality). */
  issuerDer: Uint8Array;
  /** raw DER of the subject Name. */
  subjectDer: Uint8Array;
  /**
   * basicConstraints cA flag. true → CA cert, false → end-entity / not asserted.
   * (Absence of the extension or cA=FALSE both yield false → treated as
   * end-entity, the secure default.)
   */
  isCa: boolean;
  /**
   * signature value (BIT STRING content, minus the leading unused-bits byte).
   * For EC issuers this is the DER ECDSA-Sig-Value; for RSA issuers this is the
   * raw RSA signature octet string (the BIT STRING content directly).
   */
  signature: Uint8Array;
  /** SubjectPublicKeyInfo content: the EC point bytes (uncompressed 0x04||X||Y for P-384). */
  publicKeyPoint: Uint8Array;
  /** full SubjectPublicKeyInfo element DER (for pinning + WebCrypto "spki" import). */
  spki: Uint8Array;
  /** SubjectPublicKeyInfo algorithm OID (dotted-decimal): which key type this cert HOLDS. */
  spkiAlgOid: string;
  /** AMD extensions (OID 1.3.6.1.4.1.3704.*) → extnValue content, e.g. a VCEK's hwID and SPLs. */
  amdExtensions: Map<string, Uint8Array>;
}

/**
 * Parse an X.509 certificate (DER) into the fields we need for chain
 * verification. Handles both EC (P-384) and RSA SubjectPublicKeyInfos; the
 * caller routes the verify by the issuer's `spkiAlgOid`.
 */
function parseCertDer(der: Uint8Array): ParsedCert {
  const cert = readTLV(der, 0); // outer SEQUENCE { tbs, sigAlg, sigValue }
  if (cert.tag !== 0x30) throw new Error("cert: expected SEQUENCE");
  const top = children(cert.content);
  if (top.length < 3) throw new Error("cert: too few elements");
  const tbsEl = top[0]!;
  const sigValueEl = top[2]!;
  if (tbsEl.tag !== 0x30) throw new Error("cert: TBS not a SEQUENCE");
  if (sigValueEl.tag !== 0x03) throw new Error("cert: signature not a BIT STRING");

  // signature BIT STRING: first content byte = unused-bits count (must be 0),
  // remainder is either the DER ECDSA-Sig-Value (EC issuer) or the raw RSA
  // signature octets (RSA issuer). We hand it to the right verifier downstream.
  const sigBits = sigValueEl.content;
  if (sigBits.length < 1) throw new Error("cert: empty signature");
  const sigBytes = sigBits.subarray(1); // drop unused-bits byte

  // SubjectPublicKeyInfo is field index 6 inside TBS for v3 certs:
  // [version]EXPLICIT, serial, sigAlg, issuer, validity, subject, SPKI, ...
  const tbsKids = children(tbsEl.content);
  // version is a context [0] tag (0xA0); if present, fields shift by 1.
  const hasVersion = tbsKids[0]!.tag === 0xa0;
  const base = hasVersion ? 1 : 0;
  // indices (relative to base): 0 serial, 1 sigAlg, 2 issuer, 3 validity,
  // 4 subject, 5 SPKI, [6..] optional uniqueIDs / extensions.
  const issuerEl = tbsKids[base + 2];
  const validityEl = tbsKids[base + 3];
  const subjectEl = tbsKids[base + 4];
  if (!issuerEl || issuerEl.tag !== 0x30) throw new Error("cert: issuer Name missing");
  if (!subjectEl || subjectEl.tag !== 0x30) throw new Error("cert: subject Name missing");
  if (!validityEl || validityEl.tag !== 0x30) throw new Error("cert: validity missing");
  const validityKids = children(validityEl.content);
  if (validityKids.length < 2) throw new Error("cert: validity needs 2 times");
  const notBefore = parseAsn1Time(validityKids[0]!);
  const notAfter = parseAsn1Time(validityKids[1]!);

  // Extensions live in a context [3] EXPLICIT (tag 0xA3) wrapping a SEQUENCE
  // OF Extension. Each Extension is SEQUENCE { extnID OID, critical BOOLEAN
  // DEFAULT FALSE, extnValue OCTET STRING }. We decode cA from
  // basicConstraints (absent → end-entity) and keep AMD's own extensions.
  let isCa = false;
  const amdExtensions = new Map<string, Uint8Array>();
  const extWrap = tbsKids.find((k) => k.tag === 0xa3);
  if (extWrap) {
    const extSeq = children(extWrap.content)[0];
    if (extSeq && extSeq.tag === 0x30) {
      for (const ext of children(extSeq.content)) {
        if (ext.tag !== 0x30) continue;
        const ek = children(ext.content);
        const idEl = ek[0];
        if (!idEl || idEl.tag !== 0x06) continue;
        const oid = decodeOid(idEl.content);
        // extnValue is the last element (OCTET STRING); after optional critical.
        const valEl = ek[ek.length - 1];
        if (!valEl || valEl.tag !== 0x04) continue;
        if (oid.startsWith("1.3.6.1.4.1.3704.")) {
          amdExtensions.set(oid, valEl.content);
          continue;
        }
        if (oid !== OID_BASIC_CONSTRAINTS) continue;
        // OCTET STRING wraps a SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }.
        const inner = children(valEl.content)[0];
        if (inner && inner.tag === 0x30) {
          const bcKids = children(inner.content);
          const caBool = bcKids[0];
          if (caBool && caBool.tag === 0x01 && caBool.content.length >= 1) {
            isCa = caBool.content[0]! !== 0x00;
          }
        }
      }
    }
  }

  const spkiIdx = base + 5;
  const spkiEl = tbsKids[spkiIdx];
  if (!spkiEl || spkiEl.tag !== 0x30) throw new Error("cert: SPKI not found");
  // SPKI = SEQUENCE { AlgorithmIdentifier SEQUENCE { OID, params }, subjectPublicKey BIT STRING }
  const spkiKids = children(spkiEl.content);
  const algIdEl = spkiKids[0];
  if (!algIdEl || algIdEl.tag !== 0x30)
    throw new Error("cert: SPKI AlgorithmIdentifier missing");
  const oidEl = children(algIdEl.content)[0];
  if (!oidEl || oidEl.tag !== 0x06) throw new Error("cert: SPKI algorithm OID missing");
  const spkiAlgOid = decodeOid(oidEl.content);

  const pkBitString = spkiKids[1];
  if (!pkBitString || pkBitString.tag !== 0x03)
    throw new Error("cert: public key BIT STRING missing");
  const pkPoint = pkBitString.content.subarray(1); // drop unused-bits byte → 0x04||X||Y for EC

  return {
    tbs: tbsEl.full,
    notBefore,
    notAfter,
    issuerDer: issuerEl.full,
    subjectDer: subjectEl.full,
    isCa,
    signature: sigBytes,
    publicKeyPoint: pkPoint,
    spki: spkiEl.full,
    spkiAlgOid,
    amdExtensions,
  };
}

/** A small non-negative DER INTEGER (an SPL is 0..255), or null. */
function derSmallInt(value: Uint8Array | undefined): number | null {
  if (!value || value.length < 3 || value[0] !== 0x02 || value[1] !== value.length - 2 || value[1]! > 2) return null;
  let n = 0;
  for (const b of value.subarray(2)) n = (n << 8) | b;
  return n;
}

/**
 * The VCEK must be the one AMD derived for the report's chip and TCB: its
 * hwID and SPL extensions equal the report's CHIP_ID and REPORTED_TCB. Without
 * this, a VCEK that didn't come straight from a KDS lookup for this report
 * (a cached or mirrored copy) could be another genuine one, e.g. an older,
 * vulnerable TCB's, whose leaked key signs a report claiming a newer TCB.
 */
function vcekBindingError(vcek: ParsedCert, chipId: Uint8Array, tcb: ReportedTcb): string | null {
  // Genoa/Milan VCEKs hold the raw 64-byte chip id; accept a DER OCTET STRING too.
  const hwId = vcek.amdExtensions.get(OID_AMD_HWID);
  const id = hwId && hwId.length === 66 && hwId[0] === 0x04 && hwId[1] === 0x40 ? hwId.subarray(2) : hwId;
  if (!id || !bytesEqual(id, chipId)) return "VCEK hwID != report CHIP_ID (VCEK for another chip)";
  for (const comp of Object.keys(OID_AMD_SPL) as (keyof ReportedTcb)[]) {
    const spl = derSmallInt(vcek.amdExtensions.get(OID_AMD_SPL[comp]));
    if (spl !== tcb[comp]) return `VCEK ${comp} SPL ${spl ?? "missing"} != reported ${tcb[comp]} (VCEK for another TCB)`;
  }
  return null;
}

function pemToDer(pem: string): Uint8Array {
  const m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  const b64 = (m ? m[1]! : pem).replace(/[\r\n\s]/g, "");
  return base64ToBytes(b64);
}

/** Split a PEM bundle into individual DER certs (KDS cert_chain = ASK then ARK). */
function pemBundleToDers(pem: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) out.push(pemToDer(m[0]));
  return out;
}

const subtle = globalThis.crypto.subtle;

/**
 * Verify a cert-chain link where the ISSUER's key is RSA: AMD signs ARK (self),
 * ASK and VCEK certificates with RSASSA-PSS over SHA-384 (MGF1-SHA-384, salt 48).
 *
 * `issuerSpkiDer` is the issuer cert's full SubjectPublicKeyInfo DER; `tbs` is
 * the subject cert's TBSCertificate bytes; `signature` is the raw RSA signature
 * octets (BIT STRING content). WebCrypto natively supports RSA-PSS verification.
 */
async function verifyRsaPss(
  issuerSpkiDer: Uint8Array,
  tbs: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const key = await subtle.importKey(
      "spki",
      issuerSpkiDer as unknown as BufferSource,
      { name: "RSA-PSS", hash: "SHA-384" },
      false,
      ["verify"],
    );
    return await subtle.verify(
      { name: "RSA-PSS", saltLength: 48 },
      key,
      signature as unknown as BufferSource,
      tbs as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}

/**
 * Verify an ECDSA-P384/SHA-384 signature using WebCrypto. `vcekSpkiDer` is the
 * VCEK cert's SubjectPublicKeyInfo DER (id-ecPublicKey / P-384). `rawSig` is the
 * 96-byte r||s big-endian (WebCrypto's "raw" ECDSA encoding). `message` is the
 * unhashed signed bytes (WebCrypto hashes with SHA-384 internally).
 */
async function verifyEcdsaP384(
  vcekSpkiDer: Uint8Array,
  rawSig: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  try {
    const key = await subtle.importKey(
      "spki",
      vcekSpkiDer as unknown as BufferSource,
      { name: "ECDSA", namedCurve: "P-384" },
      false,
      ["verify"],
    );
    return await subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      key,
      rawSig as unknown as BufferSource,
      message as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}

// ── pinned AMD root keys (ARK SubjectPublicKeyInfo, DER, base64) ─────────────
// The ARK is the trust anchor. We do NOT trust KDS to give us an honest root:
// the fetched ARK's SPKI must byte-match one of these. To populate/refresh,
// fetch https://kdsintf.amd.com/vcek/v1/<Product>/cert_chain (ASK,ARK PEM),
// take the ARK, and base64 its SubjectPublicKeyInfo DER. We additionally
// self-verify the ARK signature, so an embedded SPKI alone is the anchor.
//
// A product with no pin fails closed: `verifyEnclave` records "ARK not pinned
// for <product>" and chainVerified stays false. Milan is listed but unpinned.
// Genoa ARK pinned from AMD KDS (https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain,
// CN=ARK-Genoa, O=Advanced Micro Devices) — base64(DER SubjectPublicKeyInfo).
// Reproduce: openssl x509 -in <ARK> -noout -pubkey | openssl pkey -pubin -outform DER | base64 -w0
const PINNED_ARK_SPKI_B64: Record<string, string[]> = {
  Genoa: [
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3Cd95S/uFOuRIskW9vz9VDBF69NDQF79oRhL/L2PVQGhK3YdfEBgpF/JiwWFBsT/fXDhzA01p3LkcT/7LdjcRfKXjHl+0Qq/M4dZkh6QDoUeKzNBLDcBKDDGWo3v35NyrxbA1DnkYwUKU5AAk4P94tKXLp80oxt84ahyHoLmc/LqsGsp+oq1Bz4PPsYLwTG4iMKVaaT90/oZ4I8oibSru92vJhlqWO27d/Rxc3iUMyhNeGToOvgx/iUo4gGpG61NDpkEUvIzuKcaMx8IdTpWg2DF6SwF0IgVMffnvtJmA68BwJNWo1E4PLJdaPfBifcJpuBFwNVQIPQEVX3aP89HJSp8YbY9lySS6PlVEqTBBtaQmi4ATGmMR+n2K/e+JAhU2Gj7jIpJhOkdH9firQDnmlA2SFfJ/Cc0mGNzW9RmIhyOUnNFoclmkRhl3/AQU5Ys9Qsan1jT/EiyT+pCpmnA+y9edvhDCbOG8F2oxHGRdTBkylungrkXJGYiwGrR8kaiqv7NN8QhOBMqYjcbrkEr0f8QMKklIS5ruOfqlLMCBw8JLB3LkjpWgtD7OpxkzSsohN47Uom86RY6lp72g8eXHP1qYrnvhzaG1S70vw6OkbaaC9EjiH/uHgAJQGxon7u0Q7xgoREWA/e7JcBQwLg80Hq/sbRuqesxz7wBWSY254cCAwEAAQ==",
  ],
  Milan: [],
};

interface FetchedChain {
  vcek: ParsedCert;
  ask: ParsedCert;
  ark: ParsedCert;
}

/**
 * Fetch with retry/backoff for KDS rate limiting. KDS returns HTTP 429 when
 * VCEK fetches are throttled; we retry with exponential backoff (honoring
 * Retry-After when present) so a transient throttle doesn't fail attestation.
 */
async function fetchWithRetry(
  fetchFn: typeof fetch,
  url: string,
  label: string,
  maxRetries = 4,
): Promise<Response> {
  let lastStatus = 0;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const res = await fetchFn(url);
    if (res.ok) return res;
    lastStatus = res.status;
    // Only retry on rate-limit / transient server errors.
    if (res.status !== 429 && res.status < 500) {
      throw new Error(`KDS ${label} fetch: HTTP ${res.status}`);
    }
    if (attempt === maxRetries) break;
    const retryAfter = Number(res.headers.get("retry-after"));
    const backoffMs = Number.isFinite(retryAfter) && retryAfter > 0
      ? Math.min(retryAfter * 1000, 10_000)
      : Math.min(500 * 2 ** attempt, 8_000);
    await new Promise((r) => setTimeout(r, backoffMs));
  }
  throw new Error(`KDS ${label} fetch: HTTP ${lastStatus} (after retries)`);
}

/** The VCEK (DER) and ASK,ARK bundle (PEM) as KDS serves them. */
interface ChainBytes {
  vcekDer: Uint8Array;
  chainPem: string;
  /** Served by the host's KDS mirror rather than AMD. */
  mirrored?: boolean;
}

let kdsMirror: { baseUrl: string; timeoutMs: number } | null = null;

/**
 * Ask a copy of AMD KDS on the host's own origin (e.g. "/attest/kds") before
 * kdsintf.amd.com; null (the default) asks AMD only. The mirror is not
 * trusted: what it serves is verified to the pinned ARK like anything else,
 * and a copy that fails is fetched again straight from AMD. A mirror that
 * hasn't answered within `timeoutMs` is skipped for AMD.
 */
export function setKdsMirror(baseUrl: string | null, timeoutMs = 6_000): void {
  kdsMirror = baseUrl ? { baseUrl: baseUrl.replace(/\/+$/, ""), timeoutMs } : null;
}

async function fetchChainBytes(
  fetchFn: typeof fetch,
  product: string,
  chipIdHex: string,
  tcb: ReportedTcb,
  useMirror: boolean,
): Promise<ChainBytes> {
  const params =
    `?blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}` +
    `&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`;
  const vcekPath = `/vcek/v1/${product}/${chipIdHex}${params}`;
  const chainPath = `/vcek/v1/${product}/cert_chain`;

  const mirror = useMirror ? kdsMirror : null;
  if (mirror) {
    try {
      const signal = AbortSignal.timeout(mirror.timeoutMs);
      const [vcekRes, chainRes] = await Promise.all([
        fetchFn(`${mirror.baseUrl}${vcekPath}`, { signal }),
        fetchFn(`${mirror.baseUrl}${chainPath}`, { signal }),
      ]);
      if (vcekRes.ok && chainRes.ok) {
        return { vcekDer: new Uint8Array(await vcekRes.arrayBuffer()), chainPem: await chainRes.text(), mirrored: true };
      }
    } catch {
      // the mirror is unreachable: ask AMD
    }
  }

  const [vcekRes, chainRes] = await Promise.all([
    fetchWithRetry(fetchFn, `${KDS_BASE}${vcekPath}`, "VCEK"),
    fetchWithRetry(fetchFn, `${KDS_BASE}${chainPath}`, "cert_chain"),
  ]);

  // VCEK endpoint returns raw DER (application/octet-stream).
  return { vcekDer: new Uint8Array(await vcekRes.arrayBuffer()), chainPem: await chainRes.text() };
}

function parseChainBytes({ vcekDer, chainPem }: ChainBytes): FetchedChain {
  const ders = pemBundleToDers(chainPem); // [ASK, ARK]
  if (ders.length < 2) throw new Error("KDS cert_chain: expected ASK + ARK");

  return {
    vcek: parseCertDer(vcekDer),
    ask: parseCertDer(ders[0]!),
    ark: parseCertDer(ders[1]!),
  };
}

// ── VCEK + cert chain cache ──────────────────────────────────────────────────
// KDS rate-limits per IP (HTTP 429), and a chip's VCEK for one TCB never
// changes, so fetched certs are reused: in memory by every client on the page
// (attestations running at the same time share one fetch) and, when the host
// provides storage, across page loads. Nothing is trusted for being cached:
// every attestation verifies the chain to the pinned ARK and the report
// signature against the VCEK, and a cached copy that fails is fetched again.

/** Where fetched certs persist across page loads (e.g. localStorage). */
export interface VcekCacheStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

let vcekStorage: VcekCacheStorage | null = null;
const vcekMemory = new Map<string, Promise<ChainBytes>>();

/** Persist verified VCEKs and cert chains in `storage`; null (the default) keeps them in memory only. */
export function setVcekCacheStorage(storage: VcekCacheStorage | null): void {
  vcekStorage = storage;
}

/** Forget the VCEKs and chains held in memory (tests). */
export function resetVcekCache(): void {
  vcekMemory.clear();
}

const tcbKey = (tcb: ReportedTcb) => `${tcb.bootloader}.${tcb.tee}.${tcb.snp}.${tcb.microcode}`;
const memoryKey = (product: string, chipIdHex: string, tcb: ReportedTcb) => `${product}/${chipIdHex}/${tcbKey(tcb)}`;
// One entry per chip: a TCB update replaces it.
const storageKey = (product: string, chipIdHex: string) => `leokit-shielded.vcek.v1.${product}.${chipIdHex}`;

function readStoredChain(product: string, chipIdHex: string, tcb: ReportedTcb): ChainBytes | null {
  try {
    const raw = vcekStorage?.getItem(storageKey(product, chipIdHex));
    if (!raw) return null;
    const stored = JSON.parse(raw) as { tcb?: unknown; vcek?: unknown; chain?: unknown };
    if (stored.tcb !== tcbKey(tcb) || typeof stored.vcek !== "string" || typeof stored.chain !== "string") return null;
    return { vcekDer: base64ToBytes(stored.vcek), chainPem: stored.chain };
  } catch {
    return null;
  }
}

function storeChain(product: string, chipIdHex: string, tcb: ReportedTcb, bytes: ChainBytes): void {
  try {
    vcekStorage?.setItem(
      storageKey(product, chipIdHex),
      JSON.stringify({ tcb: tcbKey(tcb), vcek: bytesToBase64(bytes.vcekDer), chain: bytes.chainPem }),
    );
  } catch {
    /* quota / private mode: memory only */
  }
}

function dropChain(product: string, chipIdHex: string, tcb: ReportedTcb): void {
  vcekMemory.delete(memoryKey(product, chipIdHex, tcb));
  try {
    vcekStorage?.removeItem(storageKey(product, chipIdHex));
  } catch {
    /* nothing stored */
  }
}

/**
 * The VCEK and chain for this chip and TCB: from memory or storage, else one
 * fetch (the host's mirror, then AMD) shared by every attestation that asks
 * meanwhile. `fresh` skips both caches and the mirror.
 */
async function loadChainBytes(
  fetchFn: typeof fetch,
  product: string,
  chipIdHex: string,
  tcb: ReportedTcb,
  fresh: boolean,
): Promise<{ bytes: ChainBytes; cached: boolean }> {
  const key = memoryKey(product, chipIdHex, tcb);
  if (!fresh) {
    const held = vcekMemory.get(key);
    if (held) return { bytes: await held, cached: true };
    const stored = readStoredChain(product, chipIdHex, tcb);
    if (stored) {
      vcekMemory.set(key, Promise.resolve(stored));
      return { bytes: stored, cached: true };
    }
  }
  const fetching = fetchChainBytes(fetchFn, product, chipIdHex, tcb, !fresh);
  vcekMemory.set(key, fetching);
  fetching.catch(() => {
    if (vcekMemory.get(key) === fetching) vcekMemory.delete(key);
  });
  return { bytes: await fetching, cached: false };
}

/** Assert the issuer cert holds an RSA key (rsaEncryption or RSASSA-PSS). */
function isRsaIssuer(cert: ParsedCert): boolean {
  return cert.spkiAlgOid === OID_RSA_ENCRYPTION || cert.spkiAlgOid === OID_RSASSA_PSS;
}

/**
 * Verify the AMD certificate chain VCEK→ASK→ARK and pin the ARK.
 *
 * IMPORTANT: AMD's SEV-SNP trust chain is RSA, not ECDSA. ARK/ASK keys are
 * RSA-4096 and EVERY cert link (ARK self-sig, ASK←ARK, VCEK←ASK) is signed
 * with RSASSA-PSS / SHA-384 (MGF1-SHA-384, salt 48). The VCEK cert HOLDS an
 * ECDSA P-384 key (used to sign the report) but is itself RSA-PSS signed by
 * the ASK. Verifying any of these links as ECDSA always fails.
 *
 * Returns null on success, or a failure reason string.
 */
async function verifyChain(
  chain: FetchedChain,
  product: string,
  now: number,
  pinsOverride?: string[],
): Promise<string | null> {
  // The issuer of each link must be RSA (ARK and ASK are RSA-4096).
  if (!isRsaIssuer(chain.ark)) return `ARK key is not RSA (oid ${chain.ark.spkiAlgOid})`;
  if (!isRsaIssuer(chain.ask)) return `ASK key is not RSA (oid ${chain.ask.spkiAlgOid})`;

  // ARK self-signature (root attests itself): RSASSA-PSS/SHA-384.
  if (!(await verifyRsaPss(chain.ark.spki, chain.ark.tbs, chain.ark.signature))) {
    return "ARK self-signature failed";
  }
  // ASK signed by ARK: RSASSA-PSS/SHA-384 with ARK's RSA key.
  if (!(await verifyRsaPss(chain.ark.spki, chain.ask.tbs, chain.ask.signature))) {
    return "ASK→ARK signature failed";
  }
  // VCEK signed by ASK: RSASSA-PSS/SHA-384 with ASK's RSA key.
  if (!(await verifyRsaPss(chain.ask.spki, chain.vcek.tbs, chain.vcek.signature))) {
    return "VCEK→ASK signature failed";
  }

  // X.509 chain sanity (not a full RFC5280 path validation, but the load-bearing
  // pieces): ARK and ASK must be CAs; VCEK must be an end-entity; and the
  // issuer/subject names must link the chain together, ARK self-issued.
  if (!chain.ark.isCa) return "ARK is not a CA (basicConstraints cA!=true)";
  if (!chain.ask.isCa) return "ASK is not a CA (basicConstraints cA!=true)";
  if (chain.vcek.isCa) return "VCEK is a CA but must be an end-entity cert";
  if (!bytesEqual(chain.ark.subjectDer, chain.ark.issuerDer)) {
    return "ARK is not self-issued (subject != issuer)";
  }
  if (!bytesEqual(chain.ask.issuerDer, chain.ark.subjectDer)) {
    return "ASK.issuer != ARK.subject (broken chain link)";
  }
  if (!bytesEqual(chain.vcek.issuerDer, chain.ask.subjectDer)) {
    return "VCEK.issuer != ASK.subject (broken chain link)";
  }

  // Certificate validity windows must contain `now` for every cert.
  for (const [name, cert] of [
    ["ARK", chain.ark],
    ["ASK", chain.ask],
    ["VCEK", chain.vcek],
  ] as const) {
    if (now < cert.notBefore) return `${name} certificate not yet valid (notBefore)`;
    if (now > cert.notAfter) return `${name} certificate expired (notAfter)`;
  }

  // Pin the ARK against the embedded root (tests may inject a synthetic pin).
  const pins = pinsOverride ?? PINNED_ARK_SPKI_B64[product] ?? [];
  if (pins.length === 0) {
    return `ARK not pinned for ${product} (set PINNED_ARK_SPKI_B64 to complete the trust anchor)`;
  }
  const arkSpki = chain.ark.spki;
  const pinned = pins.some((b64) => bytesEqual(base64ToBytes(b64), arkSpki));
  if (!pinned) return "ARK SPKI does not match pinned AMD root";
  return null;
}

/**
 * Verify the SNP enclave attestation before sending it viewing material.
 *
 * @param client the ShieldedClient (used for baseUrl + fetch).
 * @param opts   expectedMeasurement (hex) and optional overrides.
 */
export async function verifyEnclave(
  client: ShieldedClient,
  opts: VerifyEnclaveOptions,
): Promise<VerifyEnclaveResult> {
  const reasons: string[] = [];
  const product = opts.productName ?? "Genoa";
  const fetchFn = opts.fetch ?? client.getFetch();
  let measurement = "";
  let chainVerified = false;
  let mode: string | undefined;
  let hpkePubkey = ""; // the enclave's HPKE pubkey (channel-binding target)
  let attestedPubkey = ""; // set only once the binding to this key is verified

  // 1. fresh random 32-byte nonce.
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  const nonceHex = bytesToHex(nonce);

  // 2. fetch the attestation report bound to the nonce.
  let report: Uint8Array;
  try {
    const baseUrl = client.getBaseUrl();
    const res = await fetchFn(`${baseUrl}/attestation?nonce=${nonceHex}`);
    if (!res.ok) {
      reasons.push(`/attestation: HTTP ${res.status}`);
      return { ok: false, measurement, reasons, chainVerified };
    }
    const j = (await res.json()) as {
      mode?: string;
      report_b64?: string | null;
      hpke_pubkey?: string | null;
    };
    mode = j.mode;
    hpkePubkey = j.hpke_pubkey ?? "";
    if (!j.report_b64) {
      reasons.push(
        `no report_b64 in response (mode=${j.mode ?? "unknown"}); enclave is not running under SEV-SNP`,
      );
      return { ok: false, measurement, reasons, mode, chainVerified };
    }
    report = base64ToBytes(j.report_b64);
  } catch (e) {
    reasons.push(`attestation fetch failed: ${(e as Error).message}`);
    return { ok: false, measurement, reasons, mode, chainVerified };
  }

  // parse + length check.
  if (report.length < SNP_REPORT_MIN_LEN) {
    reasons.push(`report too short: ${report.length} < ${SNP_REPORT_MIN_LEN}`);
    return { ok: false, measurement, reasons, mode, chainVerified };
  }
  const version = report[OFF_VERSION]!;
  if (version < 2) reasons.push(`unexpected report version ${version}`);

  measurement = bytesToHex(report.subarray(OFF_MEASUREMENT, OFF_MEASUREMENT + 48));

  // parse TCB + guest policy/VMPL up front so we can always report them.
  const tcb = parseReportedTcb(report);
  const policyInfo = parsePolicyInfo(report);

  // 1. TCB ROLLBACK FLOOR: reject any reported component below the configured
  // minimum. minTcb undefined → accept any (but tcb is always reported).
  if (opts.minTcb) {
    const checks: [keyof TcbVersions, number | undefined][] = [
      ["bootloader", opts.minTcb.bootloader],
      ["tee", opts.minTcb.tee],
      ["snp", opts.minTcb.snp],
      ["microcode", opts.minTcb.microcode],
    ];
    for (const [comp, min] of checks) {
      if (min !== undefined && tcb[comp] < min) {
        reasons.push(
          `TCB rollback: reported ${comp}=${tcb[comp]} < min ${min} (downgraded/vulnerable firmware)`,
        );
      }
    }
  }

  // 2. GUEST POLICY / DEBUG / VMPL.
  if (policyInfo.debugAllowed) {
    reasons.push(
      "guest policy permits DEBUG (host can read guest memory — SNP protection void)",
    );
  }
  if (opts.policy?.requireSmtDisabled && policyInfo.smtAllowed) {
    reasons.push("guest policy permits SMT (sibling-thread side-channel exposure)");
  }
  // MIGRATE_MA defaults to must-be-disabled.
  const requireMigrateMaDisabled = opts.policy?.requireMigrateMaDisabled ?? true;
  if (requireMigrateMaDisabled && policyInfo.migrateMaAllowed) {
    reasons.push("guest policy permits MIGRATE_MA (host may relocate guest secrets)");
  }
  const expectedVmpl = opts.expectedVmpl ?? 0;
  if (policyInfo.vmpl !== expectedVmpl) {
    reasons.push(`report VMPL ${policyInfo.vmpl} != expected ${expectedVmpl}`);
  }

  // 2/3. nonce (anti-replay): REPORT_DATA[0..32] == nonce.
  const reportData = report.subarray(OFF_REPORT_DATA, OFF_REPORT_DATA + 64);
  if (!bytesEqual(reportData.subarray(0, 32), nonce)) {
    reasons.push("REPORT_DATA[0..32] != nonce (stale or replayed report)");
  }
  // 3. CHANNEL BINDING: REPORT_DATA[32..64] == SHA-256(raw hpke_pubkey). This
  // ties the attested report to the exact key the UFVK will be encrypted to, so
  // a relayed/forged report can't be paired with an attacker's key. On success
  // `attestedPubkey` is the ONLY key the caller may seal the UFVK to.
  if (!hpkePubkey) {
    reasons.push("no hpke_pubkey in response (cannot verify channel binding)");
  } else {
    try {
      const pkRaw = base64ToBytes(hpkePubkey);
      const h = new Uint8Array(
        await subtle.digest("SHA-256", pkRaw as unknown as BufferSource),
      );
      if (!bytesEqual(reportData.subarray(32, 64), h)) {
        reasons.push(
          "REPORT_DATA[32..64] != SHA256(hpke_pubkey) — channel binding failed (possible relay/MITM)",
        );
      } else {
        attestedPubkey = hpkePubkey;
      }
    } catch (e) {
      reasons.push(`channel-binding check failed: ${(e as Error).message}`);
    }
  }

  // measurement match.
  const measurementCheck = matchMeasurement(opts.expectedMeasurement, report.subarray(OFF_MEASUREMENT, OFF_MEASUREMENT + 48));
  if (measurementCheck.fatal) {
    reasons.push(measurementCheck.fatal);
    return { ok: false, measurement, reasons, mode, chainVerified };
  }
  if (measurementCheck.reason) reasons.push(measurementCheck.reason);

  // 4. signature verification. The report SIGNATURE covers report[0..0x2A0)
  // and is ECDSA-P384 over SHA-384 of that range. We pass the raw signed bytes
  // to WebCrypto, which computes SHA-384 itself (never pass a pre-hashed
  // digest, which would be hashed twice).
  const signed = report.subarray(0, SIGNED_LEN);
  const sigField = report.subarray(OFF_SIGNATURE);
  const r = snpScalarToBE(sigField.subarray(0, 72));
  const s = snpScalarToBE(sigField.subarray(72, 144));
  const rs = new Uint8Array(96);
  rs.set(r, 0);
  rs.set(s, 48);

  // The VCEK holds the ECDSA P-384 key that signs the report. We verify the
  // report signature via WebCrypto against the VCEK's SubjectPublicKeyInfo DER.
  let vcekSpkiDer: Uint8Array | null = null;

  if (opts.vcekPem) {
    // ESCAPE HATCH: verify against caller-supplied VCEK only, no chain.
    try {
      const der = /-----BEGIN/.test(opts.vcekPem)
        ? pemToDer(opts.vcekPem)
        : base64ToBytes(opts.vcekPem);
      vcekSpkiDer = parseCertDer(der).spki;
    } catch (e) {
      reasons.push(`supplied vcekPem parse failed: ${(e as Error).message}`);
    }
    reasons.push(
      "chain NOT verified: using caller-supplied VCEK (vcekPem escape hatch)",
    );
  } else {
    // production path: VCEK + chain (cached, else the host's mirror or AMD KDS), verify + pin ARK.
    const chipIdHex = bytesToHex(report.subarray(OFF_CHIP_ID, OFF_CHIP_ID + 64));
    const now = opts.now ?? Date.now();
    const checkChain = async (fresh: boolean) => {
      // A copy (cached, or from the host's mirror) that doesn't verify this
      // report is fetched again straight from AMD.
      let copy = false;
      let cached = false;
      try {
        const loaded = await loadChainBytes(fetchFn, product, chipIdHex, tcb, fresh);
        cached = loaded.cached;
        copy = loaded.cached || !!loaded.bytes.mirrored;
        const chain = parseChainBytes(loaded.bytes);
        const chainErr =
          (await verifyChain(chain, product, now, opts._testArkSpkiPins)) ??
          vcekBindingError(chain.vcek, report.subarray(OFF_CHIP_ID, OFF_CHIP_ID + 64), tcb);
        const staleCopy =
          copy && (!!chainErr || !(await verifyEcdsaP384(chain.vcek.spki, rs, signed).catch(() => false)));
        if (!chainErr && !cached && !staleCopy) storeChain(product, chipIdHex, tcb, loaded.bytes);
        return { cached, staleCopy, chainErr, vcekSpki: chain.vcek.spki as Uint8Array | null };
      } catch (e) {
        return {
          cached,
          staleCopy: copy,
          chainErr: `KDS chain verification failed: ${(e as Error).message}`,
          vcekSpki: null,
        };
      }
    };
    let kds = await checkChain(false);
    if (kds.staleCopy) {
      dropChain(product, chipIdHex, tcb);
      kds = await checkChain(true);
    } else if (kds.chainErr && !kds.cached) {
      // Never reuse certs that didn't verify.
      dropChain(product, chipIdHex, tcb);
    }
    if (kds.chainErr) {
      reasons.push(kds.chainErr);
    } else {
      chainVerified = true;
    }
    vcekSpkiDer = kds.vcekSpki;
  }

  if (vcekSpkiDer) {
    let sigOk = false;
    try {
      // WebCrypto ECDSA P-384 over SHA-384: rs is 96-byte r||s big-endian
      // ("raw" encoding), message is the unhashed report[0..0x2A0).
      sigOk = await verifyEcdsaP384(vcekSpkiDer, rs, signed);
    } catch (e) {
      reasons.push(`report signature verify threw: ${(e as Error).message}`);
    }
    if (!sigOk) reasons.push("report ECDSA-P384 signature did not verify against VCEK");
  } else {
    reasons.push("no VCEK public key available to verify report signature");
  }

  // ok policy: FAIL CLOSED. `ok` is true ONLY when every required check passed,
  // i.e. NO reason was recorded by any of the gated checks AND the channel
  // binding produced an attested key AND (on the production path) the chain
  // verified. The other checks (TCB floor, DEBUG/SMT/MIGRATE policy, VMPL, cert
  // validity, X.509 chain sanity) all push a reason on failure, so requiring an
  // empty `reasons` for the gated set folds them into `ok` automatically.
  //
  // On the vcekPem escape hatch we expect exactly one informational reason
  // ("chain NOT verified: using caller-supplied VCEK ..."); that one does not
  // gate `ok`. Every other reason gates.
  const isEscapeHatchNote = (r: string): boolean =>
    r.startsWith("chain NOT verified: using caller-supplied VCEK");
  const gatingReasons = reasons.filter((r) => !isEscapeHatchNote(r));
  const noGatingFailures = gatingReasons.length === 0;

  // `ok` also requires a verified channel binding (attestedPubkey set).
  const ok =
    !!attestedPubkey &&
    noGatingFailures &&
    (opts.vcekPem ? !!vcekSpkiDer : chainVerified);

  return {
    ok,
    measurement,
    reasons,
    mode,
    chainVerified,
    attestedPubkey: attestedPubkey || undefined,
    tcb,
    policy: policyInfo,
  };
}

/**
 * Compare the report's MEASUREMENT against one or more trusted values.
 * `fatal` = the configuration itself is unusable (bad hex / empty list);
 * `reason` = a well-formed mismatch.
 */
export function matchMeasurement(
  expected: string | readonly string[],
  actual: Uint8Array,
): { fatal?: string; reason?: string } {
  const list = typeof expected === "string" ? [expected] : [...expected];
  if (list.length === 0) return { fatal: "expectedMeasurement list is empty" };
  let parsed: Uint8Array[];
  try {
    parsed = list.map(hexToBytes);
  } catch {
    return { fatal: "expectedMeasurement is not valid hex" };
  }
  const bad = parsed.find((m) => m.length !== 48);
  if (bad) return { reason: `expectedMeasurement must be 48 bytes (got ${bad.length})` };
  if (!parsed.some((m) => bytesEqual(m, actual))) {
    return { reason: "MEASUREMENT != expectedMeasurement (wrong/modified enclave image)" };
  }
  return {};
}
