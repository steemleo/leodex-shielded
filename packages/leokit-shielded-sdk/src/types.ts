// Wire types for the leokit-shielded HTTP API, matching the server's
// response shapes. This file is the client's single source of truth for them.

export interface Health {
  status: "ok";
  service: "leokit-shielded";
  version: string;
}

export type AttestationMode = "pre-tee" | "sev-snp" | "tdx";

export interface Attestation {
  mode: AttestationMode;
  policy: string;
  silicon: string | null;
  measurement: string | null;
  roadmap: string;
  notes: string;
}

export interface CreateSessionResponse {
  session_id: string;
  expires_at_unix: number;
}

export interface CacheStatus {
  path: string;
  tip: number | null;
  count: number;
}

export interface DecodedCacheStats {
  size: number;
  capacity: number;
  hits: number;
  misses: number;
  evictions: number;
}

export interface PoolInfo {
  configured_threads: number;
  current_pool_size: number;
  num_cpus: number;
}

export interface SealedCacheStats {
  size: number;
  capacity: number;
  hits: number;
  misses: number;
  evictions: number;
}

export interface SealedStatusResponse {
  db_path: string;
  key_path: string;
  blob_count: number;
  cache: SealedCacheStats;
}

export type SyncStatus = "idle" | "syncing" | "synced" | "error";

export interface ScannerStatus {
  scanned_height: number;
  tip_height: number;
  balance_zats: number;
  found_notes: number;
  state: SyncStatus;
}

export interface ScannerTip {
  upstream: string;
  height: number;
}

export interface ZecNote {
  txid: string;
  amount_zats: number;
  memo: string | null;
  shielded: boolean;
  spent: boolean;
}

export interface ScanOutcome {
  from_height: number;
  to_height: number;
  last_height_scanned: number;
  blocks_scanned: number;
  notes_found: number;
  total_received_zats: number;
  notes: ZecNote[];
}

export interface BroadcastOutcome {
  upstream: string;
  error_code: number;
  error_message: string;
  txid_hint: string;
}

/**
 * Per-note material returned in a delta. UNSPENT notes carry the full set
 * needed for client-side spend-proof generation (witness path + position +
 * rseed + recipient). SPENT notes omit the witness because there's nothing
 * to prove anymore.
 */
export interface ZecNoteWithProof extends ZecNote {
  /** Nullifier (32-byte hex). Unique per note; cannot be re-derived without the spending key. */
  nullifier: string;
  /** Position in the Sapling note commitment tree (leaf index). */
  position: number;
  /** Height of the block that mined this note (sent by the server). */
  block_height?: number;
  /** Hex of the raw recipient bytes (43 bytes: diversifier + pk_d). */
  recipient: string;
  /** Note plaintext rseed (33 bytes hex — leading version byte + 32 bytes). */
  rseed: string;
  /**
   * Authentication path for this note's commitment. Present only on
   * unspent notes — spent notes never need to be proven again.
   * Array of 32 hex hashes (Sapling tree depth). Use with `anchor`.
   */
  witness?: string[];
}

/** A spend the server observed against nullifiers we sent in `known_nullifiers`. */
export interface SpentRecord {
  nullifier: string;
  /** Block height at which the spend was mined. */
  height: number;
}

/**
 * Result of /scanner/delta. The endpoint returns notes newly discovered
 * since `from_height` PLUS any nullifiers from `known_nullifiers` that were
 * spent in the scanned range.
 */
export interface DeltaOutcome {
  from_height: number;
  /** Last height fully scanned. Use as `from_height + 1` for the next call. */
  to_height: number;
  blocks_scanned: number;
  /**
   * Notes newly discovered in this delta. Each carries position + witness
   * (if unspent) so a client can construct spend proofs without re-scanning.
   */
  notes: ZecNoteWithProof[];
  notes_found: number;
  /** Gross received in this delta (sum of `notes[].amount_zats`). */
  received_zats: number;
  /**
   * Net change in spendable balance from this delta = received minus any
   * spends detected (whether the spent note was in `known_nullifiers` OR
   * discovered + spent within the same scan range). Use this as the
   * authoritative per-delta balance change.
   */
  net_received_zats?: number;
  /**
   * Nullifiers from `known_nullifiers` that were spent in the scanned
   * range, with the height the spend was mined at.
   */
  spent: SpentRecord[];
  /** True if the server computed nullifiers on this scan; false on legacy paths. */
  nullifiers_computed?: boolean;
  /**
   * Sapling commitment tree root at `anchor_height`. Use this as the
   * `anchor` input when constructing spend proofs from the witnesses
   * delivered in this delta. (32-byte hex.)
   */
  anchor?: string;
  /** Height at which the `anchor` was computed (typically equal to `to_height`). */
  anchor_height?: number;
  elapsed_ms?: number;
}

export interface ApiError {
  error: string;
}

/**
 * A reply to a sealed request that the enclave didn't seal, or that doesn't
 * open under the per-request key. The enclave always seals these replies, so
 * something between the client and the attested enclave made or changed it;
 * it is refused, never read as data.
 */
/**
 * The enclave could not be attested (SEV-SNP report, AMD chain, measurement or
 * channel binding), so nothing was sealed or sent. `reasons` says why.
 */
export class ShieldedAttestationError extends Error {
  readonly code = "SHIELDED_ATTESTATION_FAILED";

  constructor(public readonly reasons: string[]) {
    super(`enclave attestation failed: ${reasons.join("; ") || "unknown"}`);
    this.name = "ShieldedAttestationError";
  }
}

export class ShieldedReplyIntegrityError extends Error {
  readonly code = "SHIELDED_REPLY_UNVERIFIED";

  constructor(
    public readonly reason: "unsealed" | "unopenable",
    public readonly path: string,
  ) {
    super(
      reason === "unsealed"
        ? `leokit-shielded reply to ${path} was not sealed by the enclave; refusing it`
        : `leokit-shielded reply to ${path} does not open under this request's key; refusing it`,
    );
    this.name = "ShieldedReplyIntegrityError";
  }
}

export class ShieldedHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly payload: ApiError | string,
  ) {
    super(
      typeof payload === "string"
        ? `leokit-shielded HTTP ${status}: ${payload}`
        : `leokit-shielded HTTP ${status}: ${payload.error}`,
    );
    this.name = "ShieldedHttpError";
  }
}
