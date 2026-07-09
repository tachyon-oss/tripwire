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
    // Placement BACKING cell carries the underlying + target file.
    expect(stdout).toContain("aws.access_key → ~/.aws/config");
    expect(stdout).toContain("aws.access_key → ~/.aws/credentials");
  });

  it("includes a VERBS column with the lifecycle verbs", () => {
    runTypes(undefined, {});
    expect(stdout).toContain("VERBS");
    expect(stdout).toContain("disarm delete");
    expect(stdout).not.toContain("arm disarm");
    expect(stdout).not.toContain("rotate");
  });

  it("shows github.token but keeps unreleased/operator types out of the catalog", () => {
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
    // Placement backing is the underlying's real backing (not the display arrow).
    expect(profile?.["backing"]).toBe("real IAM key");
    expect(profile?.["verbs"]).toEqual(["disarm", "delete"]);
    // Aliases are no longer a concept in the catalog output.
    expect(raw).not.toHaveProperty("aliases");
    expect(profile).not.toHaveProperty("aliases");
  });
});

describe("canary types <placement> explain", () => {
  it("explains aws.profile instead of erroring", () => {
    expect(() => runTypes("aws.profile", {})).not.toThrow();
    expect(stdout).toContain("aws.profile");
    expect(stdout).toContain("CLI sugar over aws.access_key");
    expect(stdout).toContain("creates:");
    expect(stdout).toContain("real IAM key");
    expect(stdout).toContain("renders:");
    expect(stdout).toContain("[profile <name>]");
    expect(stdout).toContain("--name");
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
