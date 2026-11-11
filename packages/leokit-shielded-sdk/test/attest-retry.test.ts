import { afterEach, describe, expect, it, vi } from "vitest";
import { ShieldedAttestationError, ShieldedClient } from "../src";

/** An enclave that can't be attested (no SEV-SNP report), with every request counted. */
function enclave() {
  const calls: string[] = [];
  const fetchFn = (async (url: string | URL) => {
    calls.push(new URL(String(url)).pathname);
    return new Response(JSON.stringify({ mode: "pre-tee", report_b64: null, hpke_pubkey: null }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  const client = new ShieldedClient({ baseUrl: "https://shielded.test", fetch: fetchFn, expectedMeasurement: "ab".repeat(48) });
  return { calls, client };
}

afterEach(() => vi.restoreAllMocks());

describe("attestation failures don't hammer AMD KDS", () => {
  it("seals at the same time share one attestation", async () => {
    const { calls, client } = enclave();
    const results = await Promise.allSettled([client.attest(), client.attest(), client.walletAddress("uview1test")]);
    for (const r of results) {
      expect(r.status).toBe("rejected");
      expect((r as PromiseRejectedResult).reason).toBeInstanceOf(ShieldedAttestationError);
    }
    expect(calls).toEqual(["/attestation"]);
  });

  it("after a failure, seals fail fast with the same error for a minute, then attest again", async () => {
    const { calls, client } = enclave();
    const t0 = Date.now();
    const now = vi.spyOn(Date, "now").mockReturnValue(t0);
    const first = await client.attest().catch((e: unknown) => e);
    expect(first).toBeInstanceOf(ShieldedAttestationError);
    expect((first as ShieldedAttestationError).reasons.join(" ")).toMatch(/no report_b64/);

    now.mockReturnValue(t0 + 59_000);
    await expect(client.walletAddress("uview1test")).rejects.toBe(first);
    expect(calls).toEqual(["/attestation"]);

    now.mockReturnValue(t0 + 61_000);
    await expect(client.attest()).rejects.toBeInstanceOf(ShieldedAttestationError);
    expect(calls).toEqual(["/attestation", "/attestation"]);
  });
});
