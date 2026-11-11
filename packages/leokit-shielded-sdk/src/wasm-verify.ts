/**
 * Integrity check for remotely hosted WASM modules.
 *
 * A web app that fetches the Zcash signer over the network would otherwise
 * trust every server and cache on the way to serve the right bytes. A swapped
 * signer could exfiltrate the user's seed or spending key. This helper closes that gap by
 * fetching the bytes, computing their SHA-256 with WebCrypto, and comparing
 * against a hash pinned in the application source. Anything other than an
 * exact match throws — callers MUST fail closed (never instantiate).
 *
 * Browser-safe: depends only on the standard `fetch` + `crypto.subtle` APIs.
 * No Node built-ins, no streaming instantiation (which cannot be hash-checked
 * before the module runs — by the time `instantiateStreaming` resolves, the
 * untrusted bytes have already been compiled).
 */

/** Lowercase hex of a byte array (no separators). */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Constant-time-ish comparison of two hex strings.
 *
 * Avoids the early-return timing leak of `a === b`. This is defence-in-depth:
 * the hash is not secret, but a constant-time compare removes any incentive to
 * reason about whether a timing side-channel could matter here.
 *
 * Comparison is case-insensitive (hashes may be pinned in either case) and
 * length-aware (length mismatch always fails, but we still walk the shorter
 * input so the loop count depends only on input lengths, not their contents).
 */
function timingSafeHexEqual(a: string, b: string): boolean {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  let diff = x.length ^ y.length;
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Fetch a WASM module and verify its SHA-256 against a pinned hex hash BEFORE
 * the caller is allowed to compile/instantiate it.
 *
 * @param url               Absolute URL of the `*_bg.wasm` artifact.
 * @param expectedSha256Hex Pinned SHA-256, 64 hex chars (case-insensitive).
 * @param fetchFn           Injectable fetch (defaults to global `fetch`),
 *                          for testing and non-default network contexts.
 * @returns The verified raw bytes as an ArrayBuffer (suitable for
 *          `WebAssembly.compile`).
 * @throws  If the fetch fails, the response is not OK, WebCrypto is
 *          unavailable, the pinned hash is malformed, or the computed digest
 *          does not match. The error message always starts with
 *          "WASM integrity check failed" on a digest mismatch so callers /
 *          UIs can surface a consistent message.
 */
export async function fetchVerifiedWasm(
  url: string,
  expectedSha256Hex: string,
  fetchFn: typeof fetch = fetch,
): Promise<ArrayBuffer> {
  const expected = expectedSha256Hex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    throw new Error(
      `WASM integrity check failed: malformed pinned SHA-256 for ${url} ` +
        `(expected 64 hex chars, got ${expectedSha256Hex.length})`,
    );
  }

  if (
    typeof crypto === "undefined" ||
    typeof crypto.subtle === "undefined" ||
    typeof crypto.subtle.digest !== "function"
  ) {
    throw new Error(
      `WASM integrity check failed: WebCrypto (crypto.subtle.digest) is ` +
        `unavailable; cannot verify ${url}. Refusing to load unverified WASM.`,
    );
  }

  let resp: Response;
  try {
    resp = await fetchFn(url, { method: "GET", cache: "force-cache" });
  } catch (e) {
    throw new Error(
      `WASM integrity check failed: network error fetching ${url}: ` +
        `${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (!resp.ok) {
    throw new Error(
      `WASM integrity check failed: HTTP ${resp.status} ${resp.statusText} ` +
        `fetching ${url}`,
    );
  }

  const bytes = await resp.arrayBuffer();
  if (bytes.byteLength === 0) {
    throw new Error(
      `WASM integrity check failed: empty response body for ${url}`,
    );
  }

  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const actual = toHex(new Uint8Array(digest));

  if (!timingSafeHexEqual(actual, expected)) {
    throw new Error(
      `WASM integrity check failed: SHA-256 mismatch for ${url} — ` +
        `expected ${expected}, got ${actual}. ` +
        `Refusing to instantiate (possible supply-chain tampering).`,
    );
  }

  return bytes;
}
