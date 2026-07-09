import type { Command } from "commander";
import { describe, expect, it } from "vitest";

import { buildProgram, Session } from "../src/index.js";
import { resolveType, UnknownTypeError } from "../src/types/registry.js";

function program(): Command {
  return buildProgram(new Session());
}

function canaryGroup(): Command {
  const canary = program().commands.find((c) => c.name() === "canary");
  if (!canary) throw new Error("canary group missing");
  return canary;
}

describe("removed commands", () => {
  it("has no arm or rotate subcommand", () => {
    const names = canaryGroup().commands.map((c) => c.name());
    expect(names).not.toContain("arm");
    expect(names).not.toContain("rotate");
  });

  it("exposes exactly the canonical canary subcommands", () => {
    const names = canaryGroup().commands.map((c) => c.name()).sort();
    expect(names).toEqual(["api", "create", "delete", "disarm", "list", "show", "types"]);
  });
});

describe("removed aliases", () => {
  it("gives every canary subcommand zero aliases (no ls/get/rm/enable/disable)", () => {
    for (const sub of canaryGroup().commands) {
      expect(sub.aliases()).toEqual([]);
    }
  });

  it("has no `canaries` group and no `canaries` alias anywhere at top level", () => {
    const top = program().commands;
    expect(top.map((c) => c.name())).not.toContain("canaries");
    for (const c of top) expect(c.aliases()).not.toContain("canaries");
  });
});

describe("removed back-compat flags", () => {
  it("create has no --type flag (type is positional only)", () => {
    const create = canaryGroup().commands.find((c) => c.name() === "create");
    const longs = create?.options.map((o) => o.long) ?? [];
    expect(longs).not.toContain("--type");
    // The flags that remain are present; --in (unsupported) and --name
    // (the backend now generates the placement name) are gone.
    expect(longs).toContain("--note");
    expect(longs).toContain("--expires");
    expect(longs).toContain("--output");
    expect(longs).not.toContain("--in");
    expect(longs).not.toContain("--name");
  });
});

describe("no snake / convenience type input", () => {
  it("rejects snake wire ids and old aliases as create input", () => {
    for (const bad of ["aws_access_key", "postgres", "kubeconfig", "database", "github_pat"]) {
      expect(() => resolveType(bad)).toThrow(UnknownTypeError);
    }
  });

  it("still accepts the canonical dotted ids", () => {
    expect(resolveType("aws.access_key").wire).toBe("aws_access_key");
    expect(resolveType("k8s.config").wire).toBe("kubernetes_kubeconfig");
  });
});
