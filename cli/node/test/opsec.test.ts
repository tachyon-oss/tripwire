import { describe, expect, it } from "vitest";

import {
  assertSafeName,
  BANNED_TERMS,
  findBannedTerm,
  OpsecError,
} from "../src/placements/opsec.js";

describe("OPSEC name gate", () => {
  it("accepts mundane, organic names", () => {
    for (const name of ["prod-deploy", "s3-backups", "billing", "terraform-ci", "readonly"]) {
      expect(findBannedTerm(name)).toBeNull();
      expect(() => assertSafeName(name)).not.toThrow();
    }
  });

  it("rejects the hard-banned decoy terms", () => {
    for (const term of ["canary", "tripwire", "planted", "honeypot"]) {
      expect(findBannedTerm(term)).toBe(term);
    }
  });

  it("rejects names that merely contain a hard term", () => {
    expect(findBannedTerm("canary-x")).toBe("canary");
    expect(findBannedTerm("honeypot-y")).toBe("honeypot");
    expect(() => assertSafeName("canary-x")).toThrow(OpsecError);
    expect(() => assertSafeName("honeypot-y")).toThrow(OpsecError);
  });

  it("rejects the placement extras", () => {
    expect(findBannedTerm("honeytoken")).toBe("honeytoken");
    expect(findBannedTerm("decoy")).toBe("decoy");
    expect(findBannedTerm("bait")).toBe("bait");
    expect(findBannedTerm("trap")).toBe("trap");
  });

  it("matches the HARD terms as case-insensitive substrings", () => {
    expect(findBannedTerm("my-CANARY-key")).toBe("canary");
    expect(findBannedTerm("prod-honeypot-01")).toBe("honeypot");
    expect(findBannedTerm("TripWireThing")).toBe("tripwire");
  });

  it("matches the short generic extras only as whole words", () => {
    // Whole-word hits are rejected...
    expect(findBannedTerm("prod-trap")).toBe("trap");
    expect(findBannedTerm("decoy")).toBe("decoy");
    expect(findBannedTerm("s3-bait")).toBe("bait");
    // ...but the same fragment inside a mundane word is NOT a false-positive.
    expect(findBannedTerm("bootstrap")).toBeNull(); // contains "trap"
    expect(findBannedTerm("decoymodel")).toBeNull(); // contains "decoy"
    expect(findBannedTerm("DecoyProfile")).toBeNull();
    expect(findBannedTerm("baited-hook")).toBeNull(); // "bait" not word-bounded
    expect(() => assertSafeName("bootstrap-deploy")).not.toThrow();
  });

  it("throws a didactic OpsecError with the offending term", () => {
    try {
      assertSafeName("prod-canary");
      throw new Error("expected assertSafeName to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(OpsecError);
      expect((error as OpsecError).message).toContain("canary");
    }
  });

  it("exposes the full ban list", () => {
    // Every hard and generic term is present in the combined BANNED_TERMS.
    const terms = ["canary", "tripwire", "planted", "honeypot", "honeytoken", "decoy", "bait", "trap"];
    for (const term of terms) {
      expect(BANNED_TERMS).toContain(term);
    }
  });
});
