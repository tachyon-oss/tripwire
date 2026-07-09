import { describe, expect, it } from "vitest";

import { DEFAULT_ROLES, generateName, normalizeContext } from "../src/placements/namegen.js";

const pickFirst = (roles: readonly string[]): string => roles[0] ?? "deploy";

describe("normalizeContext", () => {
  it("lowercases and slugifies", () => {
    expect(normalizeContext("LedgerFlow API")).toBe("ledgerflow-api");
    expect(normalizeContext("my_repo.v2")).toBe("my-repo-v2");
  });

  it("trims leading/trailing separators", () => {
    expect(normalizeContext("__weird__")).toBe("weird");
  });

  it("drops empty or unusable contexts", () => {
    expect(normalizeContext("")).toBeNull();
    expect(normalizeContext("   ")).toBeNull();
    expect(normalizeContext("***")).toBeNull();
    expect(normalizeContext(null)).toBeNull();
  });

  it("drops a context that trips the OPSEC ban scan", () => {
    expect(normalizeContext("canary-lab")).toBeNull();
    expect(normalizeContext("honeypot-repo")).toBeNull();
  });
});

describe("generateName", () => {
  it("combines a safe context with a role", () => {
    const name = generateName({
      roles: DEFAULT_ROLES,
      pickRole: pickFirst,
      resolveContext: () => "billing-service",
    });
    expect(name).toBe("billing-service-deploy");
  });

  it("falls back to just the role when the context is unsafe", () => {
    const name = generateName({
      roles: DEFAULT_ROLES,
      pickRole: pickFirst,
      resolveContext: () => "tripwire-internal",
    });
    expect(name).toBe("deploy");
  });

  it("falls back to just the role when there is no context", () => {
    const name = generateName({
      roles: ["s3-sync"],
      pickRole: pickFirst,
      resolveContext: () => null,
    });
    expect(name).toBe("s3-sync");
  });

  it("only ever produces OPSEC-safe names from the default roles", () => {
    for (const role of DEFAULT_ROLES) {
      const name = generateName({
        roles: DEFAULT_ROLES,
        pickRole: () => role,
        resolveContext: () => "acme-web",
      });
      expect(name).toBe(`acme-web-${role}`);
    }
  });
});
