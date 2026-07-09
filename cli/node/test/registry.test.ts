import { describe, expect, it } from "vitest";

import {
  customerTypes,
  dottedForWire,
  resolveType,
  tryResolveType,
  UnknownTypeError,
} from "../src/types/registry.js";

describe("type registry", () => {
  it("resolves the canonical dotted ids to the snake wire id", () => {
    expect(resolveType("aws.access_key").wire).toBe("aws_access_key");
    expect(resolveType("github.token").wire).toBe("github_pat");
    expect(resolveType("database.credentials").wire).toBe("postgres_login");
    expect(resolveType("web.login").wire).toBe("web_login_credential");
    expect(resolveType("web.cookie").wire).toBe("browser_session_cookie");
    expect(resolveType("k8s.config").wire).toBe("kubernetes_kubeconfig");
  });

  it("does NOT accept snake wire ids as input (no back-compat aliasing)", () => {
    for (const snake of [
      "aws_access_key",
      "github_pat",
      "anthropic_api_key",
      "postgres_login",
      "web_login_credential",
      "browser_session_cookie",
      "kubernetes_kubeconfig",
    ]) {
      expect(() => resolveType(snake)).toThrow(UnknownTypeError);
      expect(tryResolveType(snake)).toBeUndefined();
    }
  });

  it("does NOT accept the old convenience aliases as input", () => {
    for (const alias of ["database", "postgres", "kubeconfig"]) {
      expect(() => resolveType(alias)).toThrow(UnknownTypeError);
    }
  });

  it("normalizes case and surrounding whitespace of a canonical id", () => {
    expect(resolveType("  AWS.Access_Key ").wire).toBe("aws_access_key");
  });

  it("maps a wire id the server returns back to its dotted display id", () => {
    expect(dottedForWire("aws_access_key")).toBe("aws.access_key");
    expect(dottedForWire("postgres_login")).toBe("database.credentials");
    // Unreleased and operator wire ids still map for display even though they
    // are not accepted as create input.
    expect(dottedForWire("github_pat")).toBe("github.token");
    expect(dottedForWire("anthropic_api_key")).toBe("anthropic.api_key");
    expect(dottedForWire("dns_label")).toBe("dns.label");
    // Unknown wire ids pass through unchanged (future server types).
    expect(dottedForWire("something_new")).toBe("something_new");
  });

  it("throws UnknownTypeError for an unknown type", () => {
    expect(() => resolveType("nope.nope")).toThrow(UnknownTypeError);
    expect(tryResolveType("nope.nope")).toBeUndefined();
  });

  it("shows github.token but keeps unreleased/operator types out of catalog + input", () => {
    const ids = customerTypes().map((e) => e.id);
    // github.token is released: creatable and shown.
    expect(ids).toContain("github.token");
    expect(resolveType("github.token").wire).toBe("github_pat");
    // anthropic.api_key is unreleased; dns.label is internal and not exposed in the CLI.
    expect(ids).not.toContain("anthropic.api_key");
    expect(ids).not.toContain("dns.label");
    expect(ids).toHaveLength(6);

    for (const hidden of [
      "anthropic.api_key",
      "anthropic_api_key",
      "dns.label",
      "dns_label",
    ]) {
      expect(() => resolveType(hidden)).toThrow(UnknownTypeError);
    }
  });

  it("carries the exact per-type output fields (mirrors _RESPONSE_BY_TYPE)", () => {
    expect(resolveType("aws.access_key").outputFields).toEqual([
      "access_key_id",
      "secret_access_key",
      "region",
    ]);
    expect(resolveType("web.cookie").outputFields).toEqual([
      "url",
      "cookie_name",
      "cookie_value",
      "cookie_domain",
      "cookie_path",
    ]);
  });

  it("keeps the 240s create wait floor on every type", () => {
    for (const entry of customerTypes()) {
      expect(entry.waitSeconds).toBe(240);
    }
  });
});
