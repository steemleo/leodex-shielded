import {
  Attestation,
  BroadcastOutcome,
  CacheStatus,
  CreateSessionResponse,
  DecodedCacheStats,
  DeltaOutcome,
  Health,
  PoolInfo,
  ScanOutcome,
  ScannerStatus,
  ScannerTip,
  SealedStatusResponse,
  ShieldedAttestationError,
  ShieldedHttpError,
  ShieldedReplyIntegrityError,
} from "./types";
import {
  sealUfvk,
  sealUfvkToKey,
  resetServerPubkeyCache,
  decryptResponse,
  encryptRequest,
  type SealedUfvk,
} from "./e2e";
import { verifyEnclave, type VerifyEnclaveResult } from "./attestation";

/** Minimum acceptable SEV-SNP TCB components (rollback floor). */
export interface MinTcb {
  bootloader?: number;
  tee?: number;
  snp?: number;
  microcode?: number;
}
let defaultExpectedMeasurement: string | readonly string[] | undefined;
let defaultProductName: "Genoa" | "Milan" = "Genoa";
let defaultMinTcb: MinTcb | undefined;
/**
 * Process-wide default expected launch measurement. Set once at app startup
 * (`setTrustedMeasurement(...)`); every ShieldedClient then attests against it
 * before any UFVK is sealed, so no call site can forget to gate. Per-client
 * `expectedMeasurement` overrides this.
 */
export function setTrustedMeasurement(
  measurementHex: string | readonly string[],
  productName: "Genoa" | "Milan" = "Genoa",
  minTcb?: MinTcb,
): void {
  defaultExpectedMeasurement = measurementHex;
  defaultProductName = productName;
  defaultMinTcb = minTcb;
}

/**
 * Does this HTTP error look like the server failed to decrypt our UFVK
 * envelope? That's the signature of a stale cache after the server
 * rotated its X25519 key. The server-side e2e module emits exactly this
 * error string when ChaCha20Poly1305 AEAD verification fails.
 */
function looksLikeUfvkDecryptError(e: ShieldedHttpError): boolean {
  const payload = e.payload;
  const text =
    typeof payload === "string"
      ? payload
      : payload && typeof payload.error === "string"
        ? payload.error
        : "";
  return /could not decrypt ufvk_enc|hpke|decrypt/i.test(text);
}

export interface ShieldedClientOptions {
  baseUrl: string;
  fetch?: typeof fetch;
  /**
   * Expected SEV-SNP launch measurement (48-byte hex). When set (here or via
   * setTrustedMeasurement), the client REMOTELY ATTESTS the enclave before
   * sealing any UFVK and encrypts it ONLY to the attested key — so a forged or
   * relayed endpoint can never receive a viewing key. Leave unset only for
   * local dev / non-SNP backends (insecure; logs a warning).
   */
  expectedMeasurement?: string | readonly string[];
  productName?: "Genoa" | "Milan";
  /** TCB rollback floor — reject reports from firmware below these versions. */
  minTcb?: MinTcb;
  /**
   * After a failed attestation, seals fail with the same error for this long
   * instead of attesting again (AMD KDS rate-limits per IP). Default 60 s.
   */
  attestRetryAfterMs?: number;
}

/**
 * Typed client for the leokit-shielded HTTP API.
 *
 * Trust model: only viewing material (UFVK / IVK) crosses the wire. The
 * spending key and seed NEVER leave the user's device.
 */
export class ShieldedClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly expectedMeasurement?: string | readonly string[];
  private readonly productName: "Genoa" | "Milan";
  private readonly minTcb?: MinTcb;
  /** The attested HPKE pubkey, cached after a successful attest() this session. */
  private attestedPubkey?: string;
  /** The attestation in progress: concurrent seals share it. */
  private attesting?: Promise<VerifyEnclaveResult>;
  private lastAttestFailure?: { at: number; error: ShieldedAttestationError };
  private readonly attestRetryAfterMs: number;

  constructor(opts: ShieldedClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.expectedMeasurement = opts.expectedMeasurement ?? defaultExpectedMeasurement;
    this.productName = opts.productName ?? defaultProductName;
    this.minTcb = opts.minTcb ?? defaultMinTcb;
    this.attestRetryAfterMs = opts.attestRetryAfterMs ?? 60_000;
  }

  /**
   * Remotely attest the enclave: verify the SEV-SNP report (AMD chain +
   * measurement + nonce + channel binding) and cache the attested HPKE pubkey.
   * Called automatically before the first UFVK is sealed. Throws a
   * ShieldedAttestationError on failure, and again without re-attesting until
   * `attestRetryAfterMs` has passed.
   */
  attest(): Promise<VerifyEnclaveResult> {
    this.attesting ??= this.runAttest().finally(() => {
      this.attesting = undefined;
    });
    return this.attesting;
  }

  private async runAttest(): Promise<VerifyEnclaveResult> {
    if (!this.expectedMeasurement || this.expectedMeasurement.length === 0) {
      throw new Error(
        "ShieldedClient.attest: no expectedMeasurement configured (constructor or setTrustedMeasurement)",
      );
    }
    const failed = this.lastAttestFailure;
    if (failed && Date.now() - failed.at < this.attestRetryAfterMs) throw failed.error;
    const res = await verifyEnclave(this, {
      expectedMeasurement: this.expectedMeasurement,
      productName: this.productName,
      minTcb: this.minTcb,
      fetch: this.fetchFn,
    });
    if (!res.ok || !res.attestedPubkey) {
      const error = new ShieldedAttestationError(res.reasons);
      this.lastAttestFailure = { at: Date.now(), error };
      throw error;
    }
    this.lastAttestFailure = undefined;
    this.attestedPubkey = res.attestedPubkey;
    return res;
  }

  /**
   * Seal a UFVK for transmission. Secure path: attest (once) and encrypt to the
   * ATTESTED key. Without an expectedMeasurement, falls back to the legacy
   * fetch-pubkey path and warns — insecure, dev/non-SNP only.
   */
  private async sealForUfvk(ufvk: string): Promise<SealedUfvk> {
    if (!this.expectedMeasurement) {
      // eslint-disable-next-line no-console
      console.warn(
        "[leokit-shielded-sdk] sending UFVK WITHOUT attestation (no expectedMeasurement) — insecure; dev only.",
      );
      return sealUfvk(this.baseUrl, ufvk);
    }
    if (!this.attestedPubkey) await this.attest();
    return sealUfvkToKey(this.attestedPubkey!, ufvk);
  }

  /**
   * Unwrap the reply to a sealed request. The enclave always encrypts it under
   * the per-request exporter key (`{ enc }`). TLS ends before the enclave, so a
   * plaintext reply, or one that doesn't open under this request's key, was
   * made or changed on the way: it is refused, never read as data.
   */
  private unwrapResponse<T>(raw: unknown, responseKey: Uint8Array, path: string): T {
    const enc = raw && typeof raw === "object" ? (raw as { enc?: unknown }).enc : undefined;
    if (typeof enc !== "string") throw new ShieldedReplyIntegrityError("unsealed", path);
    let plaintext: string;
    try {
      plaintext = decryptResponse(responseKey, enc);
    } catch {
      throw new ShieldedReplyIntegrityError("unopenable", path);
    }
    return JSON.parse(plaintext) as T;
  }

  /** The normalized base URL this client targets (no trailing slash). */
  getBaseUrl(): string {
    return this.baseUrl;
  }

  /** The fetch implementation this client uses (shared with verifyEnclave). */
  getFetch(): typeof fetch {
    return this.fetchFn;
  }

  health(): Promise<Health> {
    return this.get("/health");
  }

  attestation(): Promise<Attestation> {
    return this.get("/attestation");
  }

  /** Stateless ephemeral session — fresh client pubkey per session. */
  createSession(clientPubkeyHex: string): Promise<CreateSessionResponse> {
    if (!/^[0-9a-fA-F]{64}$/.test(clientPubkeyHex)) {
      throw new Error("client_pubkey must be 32 bytes hex (64 chars)");
    }
    return this.post("/session", { client_pubkey: clientPubkeyHex });
  }

  chainCacheStatus(): Promise<CacheStatus> {
    return this.get("/chain/cache/status");
  }

  decodedCacheStats(): Promise<DecodedCacheStats> {
    return this.get("/chain/decoded-cache");
  }

  poolInfo(): Promise<PoolInfo> {
    return this.get("/sync/pool");
  }

  sealedStatus(): Promise<SealedStatusResponse> {
    return this.get("/sealed/status");
  }

  scannerStatus(): Promise<ScannerStatus> {
    return this.get("/scanner/status");
  }

  scannerTip(): Promise<ScannerTip> {
    return this.get("/scanner/tip");
  }

  /**
   * Run Sapling trial decryption against a UFVK over `[birthdayHeight, toHeight ?? tip]`.
   * Returns discovered Sapling notes + the total received zatoshis.
   *
   * NO spending key crosses this call. The UFVK is view-only.
   */
  scannerScan(args: {
    sessionId?: string;
    ufvk: string;
    birthdayHeight: number;
    toHeight?: number;
  }): Promise<ScanOutcome> {
    // Gated HPKE path: the backend requires the encrypted ufvk_enc (the
    // plaintext ufvk field was removed) and the client seals to the attested key.
    // The scan-range fields are wrapped in `enc_req` so on-path observers can't
    // see the height window being scanned.
    return this.callWithHpke<ScanOutcome>("/scanner/scan", args.ufvk, (ufvk_enc, encReq) => ({
      session_id: args.sessionId,
      ufvk_enc,
      enc_req: encReq({
        birthday_height: args.birthdayHeight,
        to_height: args.toHeight ?? null,
      }),
    }));
  }

  /**
   * Relay a signed Zcash transaction (hex) to lightwalletd. The server is a
   * stateless forwarder — it does not sign, decode, or store the tx.
   */
  txBroadcast(txHex: string): Promise<BroadcastOutcome> {
    return this.post("/tx/broadcast", { tx_hex: txHex });
  }

  /**
   * Incremental scan against the server's local block cache.
   *
   * - `fromHeight` is the cursor — the wallet's birthday on first call, or
   *   `last_height_scanned + 1` from the previous response for subsequent
   *   delta polls.
   * - `knownNullifiers` is the set of nullifiers for currently-unspent
   *   notes the client believes it owns; the server returns the subset
   *   that got spent during the scanned range.
   *
   * Cheap (~seconds) compared to `/scanner/scan` from Sapling activation
   * because the server only processes blocks since `fromHeight`.
   */
  async scannerDelta(args: {
    ufvk: string;
    fromHeight: number;
    knownNullifiers?: string[];
    /**
     * Ask the server to include the Sapling witness path + position +
     * rseed + recipient for every unspent note. Required to construct
     * spend proofs client-side later. Default true.
     */
    withWitnesses?: boolean;
    /**
     * Inclusive scan ceiling (defaults to the server's cache tip). A
     * single-block range `[h, h]` re-finds the notes mined at `h` and
     * returns fresh witnesses for them against the server's current tree
     * — the cheap way to refresh old notes before spending.
     */
    toHeight?: number;
  }): Promise<DeltaOutcome> {
    // The sensitive fields (which notes the user tracks via known_nullifiers,
    // plus the sync window/with_witnesses) are wrapped in `enc_req` so
    // nothing on the way can see them. ufvk_enc stays as the HPKE envelope.
    return this.callWithHpke<DeltaOutcome>(
      "/scanner/delta",
      args.ufvk,
      (ufvk_enc, encReq) => ({
        ufvk_enc,
        enc_req: encReq(deltaRequestFields(args)),
      }),
    );
  }

  /**
   * Derive the canonical ZIP-316 unified address (u1...) for a UFVK.
   * View-only: the UFVK is already POSTed on /scanner/delta, so this call
   * leaks no new material. Used by the wallet UI to display the user's
   * receive address without loading a full wallet WASM bundle.
   */
  async walletAddress(ufvk: string): Promise<{
    unified_address: string;
    receivers: { sapling: boolean; orchard: boolean; transparent: boolean };
  }> {
    return this.callWithHpke("/wallet/address", ufvk, (ufvk_enc) => ({
      ufvk_enc,
    }));
  }

  /**
   * POST with an HPKE-sealed UFVK, retry once on a likely pubkey-rotation
   * failure. The server returns `400` with "could not decrypt ufvk_enc"
   * when its private key no longer matches what we sealed against (because
   * the server rotated it or was replaced). We bust the cached
   * server pubkey and seal again with the new one.
   */
  private async callWithHpke<T>(
    path: string,
    ufvk: string,
    bodyFn: (ufvk_enc: string, encReq: (fields: Record<string, unknown>) => string) => Record<string, unknown>,
  ): Promise<T> {
    const sealed = await this.sealForUfvk(ufvk);
    // Encrypt sensitive request fields to the per-request REQUEST key (same HPKE
    // handshake as ufvk_enc, distinct exporter context). The server decrypts with
    // e2e::open_sealed; anything on the way sees only the `enc_req` ciphertext.
    const encReq = (s: SealedUfvk) => (fields: Record<string, unknown>): string =>
      encryptRequest(s.requestKey, new TextEncoder().encode(JSON.stringify(fields)));
    try {
      const raw = await this.post<unknown>(path, bodyFn(sealed.envelope, encReq(sealed)));
      return this.unwrapResponse<T>(raw, sealed.responseKey, path);
    } catch (e) {
      if (
        e instanceof ShieldedHttpError &&
        e.status === 400 &&
        looksLikeUfvkDecryptError(e)
      ) {
        // Server key changed (rotation / redeploy with a new measurement):
        // invalidate the attested key AND the legacy pubkey cache, then
        // re-attest+reseal. If the measurement actually changed, the re-attest
        // inside sealForUfvk fails closed rather than sealing to an unverified build.
        this.attestedPubkey = undefined;
        resetServerPubkeyCache(this.baseUrl);
        const fresh = await this.sealForUfvk(ufvk);
        const raw = await this.post<unknown>(path, bodyFn(fresh.envelope, encReq(fresh)));
        return this.unwrapResponse<T>(raw, fresh.responseKey, path);
      }
      throw e;
    }
  }

  private async get<T>(path: string): Promise<T> {
    const r = await this.fetchFn(`${this.baseUrl}${path}`);
    return this.parse<T>(r);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const r = await this.fetchFn(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return this.parse<T>(r);
  }

  private async parse<T>(r: Response): Promise<T> {
    if (!r.ok) {
      const text = await r.text();
      let payload: { error: string } | string = text;
      try {
        payload = JSON.parse(text);
      } catch {
        // not JSON, keep raw text
      }
      throw new ShieldedHttpError(r.status, payload);
    }
    return (await r.json()) as T;
  }
}

/** The sensitive `/scanner/delta` fields sealed into `enc_req`. */
export function deltaRequestFields(args: {
  fromHeight: number;
  knownNullifiers?: string[];
  withWitnesses?: boolean;
  toHeight?: number;
}): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    from_height: args.fromHeight,
    known_nullifiers: args.knownNullifiers ?? [],
    with_witnesses: args.withWitnesses ?? true,
  };
  if (args.toHeight !== undefined) fields.to_height = args.toHeight;
  return fields;
}
