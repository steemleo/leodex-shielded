import { describe, expect, it } from "vitest";
import { deltaRequestFields } from "../src/client";

describe("deltaRequestFields", () => {
  it("keeps the legacy shape when no ceiling is given", () => {
    expect(deltaRequestFields({ fromHeight: 10 })).toEqual({ from_height: 10, known_nullifiers: [], with_witnesses: true });
  });

  it("seals to_height for single-block witness refreshes", () => {
    expect(deltaRequestFields({ fromHeight: 2_000_000, toHeight: 2_000_000, withWitnesses: true, knownNullifiers: ["ab"] })).toEqual({
      from_height: 2_000_000,
      to_height: 2_000_000,
      known_nullifiers: ["ab"],
      with_witnesses: true
    });
  });
});
