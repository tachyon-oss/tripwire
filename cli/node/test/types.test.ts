import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runTypes } from "../src/commands/canary.js";

/** Capture what `runTypes` writes to stdout. */
let stdout: string;

beforeEach(() => {
  stdout = "";
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  });
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("canary types catalog", () => {
  it("lists the placements nested under their underlying type", () => {
    runTypes(undefined, {});
    expect(stdout).toContain("aws.access_key");
    expect(stdout).toContain("aws.profile");
    expect(stdout).toContain("aws.credentials");
    // Placement row shows its plain description + the target file.
    expect(stdout).toContain("rendered into ~/.aws/config");
    expect(stdout).toContain("rendered into ~/.aws/credentials");
  });

  it("shows a plain description and hides internal columns (backing/fires-via/verbs)", () => {
    runTypes(undefined, {});
    expect(stdout).toContain("WHAT IT IS");
    expect(stdout).toContain("AWS access key");
    expect(stdout).not.toContain("VERBS");
    expect(stdout).not.toContain("BACKING");
    expect(stdout).not.toContain("FIRES VIA");
    expect(stdout).not.toContain("CloudTrail");
  });

  it("shows github.token but keeps unreleased/internal types out of the catalog", () => {
    runTypes(undefined, {});
    expect(stdout).toContain("github.token");
    expect(stdout).not.toContain("anthropic.api_key");
    expect(stdout).not.toContain("dns.label");
    expect(stdout).not.toMatch(/\burl\b/);
  });
});

describe("canary types --json", () => {
  it("emits placement rows carrying a placement descriptor, absent on raw types", () => {
    runTypes(undefined, { json: true });
    const rows = JSON.parse(stdout) as Array<Record<string, unknown>>;
    const raw = rows.find((r) => r["id"] === "aws.access_key");
    const profile = rows.find((r) => r["id"] === "aws.profile");
    const credentials = rows.find((r) => r["id"] === "aws.credentials");

    expect(raw).toBeDefined();
    expect(raw).not.toHaveProperty("placement");

    expect(profile?.["placement"]).toEqual({
      underlying: "aws.access_key",
      target_hint: "~/.aws/config",
    });
    expect(credentials?.["placement"]).toEqual({
      underlying: "aws.access_key",
      target_hint: "~/.aws/credentials",
    });
    // --json carries a plain summary, not internal backing/fires-via/verbs.
    expect(profile?.["summary"]).toContain("AWS access key");
    expect(profile).not.toHaveProperty("backing");
    expect(profile).not.toHaveProperty("verbs");
    // Aliases are no longer a concept in the catalog output.
    expect(raw).not.toHaveProperty("aliases");
    expect(profile).not.toHaveProperty("aliases");
  });
});

describe("canary types <placement> explain", () => {
  it("explains aws.profile instead of erroring", () => {
    expect(() => runTypes("aws.profile", {})).not.toThrow();
    expect(stdout).toContain("aws.profile");
    expect(stdout).toContain("AWS access key");
    expect(stdout).toContain("rendered into ~/.aws/config");
    expect(stdout).not.toContain("real IAM key");
    expect(stdout).toContain("[profile <name>]");
    expect(stdout).toContain("-o/--output");
    expect(stdout).toContain("tripwire canary create aws.profile >> ~/.aws/config");
  });

  it("explains aws.credentials with a bare-header sample block", () => {
    runTypes("aws.credentials", {});
    expect(stdout).toContain("[<name>]");
    expect(stdout).not.toContain("[profile <name>]");
  });

  it("returns explain detail as JSON for a placement", () => {
    runTypes("aws.profile", { json: true });
    const detail = JSON.parse(stdout) as Record<string, unknown>;
    expect(detail["id"]).toBe("aws.profile");
    expect(detail["wire"]).toBe("aws_access_key");
    expect(detail["placement"]).toEqual({
      underlying: "aws.access_key",
      target_hint: "~/.aws/config",
    });
    expect(detail["example"]).toBe(
      "tripwire canary create aws.profile >> ~/.aws/config",
    );
  });
});
