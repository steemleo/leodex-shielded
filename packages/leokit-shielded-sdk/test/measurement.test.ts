import { describe, expect, it } from "vitest";
import { matchMeasurement } from "../src/attestation";

const hex = (b: number) => b.toString(16).padStart(2, "0").repeat(48);
const bytes = (b: number) => new Uint8Array(48).fill(b);

describe("matchMeasurement", () => {
  it("accepts the single pinned measurement", () => {
    expect(matchMeasurement(hex(0xaa), bytes(0xaa))).toEqual({});
  });

  it("accepts any entry of an allow-list (rotation window)", () => {
    expect(matchMeasurement([hex(0x11), hex(0xbb)], bytes(0xbb))).toEqual({});
    expect(matchMeasurement([hex(0x11), hex(0xbb)], bytes(0x11))).toEqual({});
  });

  it("rejects a report outside the allow-list", () => {
    expect(matchMeasurement([hex(0x11), hex(0x22)], bytes(0x33)).reason).toMatch(/MEASUREMENT != expectedMeasurement/);
  });

  it("treats an empty list or bad hex as fatal configuration errors", () => {
    expect(matchMeasurement([], bytes(0x11)).fatal).toMatch(/empty/);
    expect(matchMeasurement("zz", bytes(0x11)).fatal).toMatch(/not valid hex/);
  });

  it("rejects a wrong-length measurement", () => {
    expect(matchMeasurement("aa", bytes(0xaa)).reason).toMatch(/48 bytes/);
  });
});
