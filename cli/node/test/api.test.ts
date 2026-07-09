import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiClient, RawResponse } from "../src/api/client.js";
import { CREATE_READ_TIMEOUT_MS } from "../src/api/client.js";
import { runApi } from "../src/commands/api.js";
import { CredentialStore } from "../src/config/credentials.js";
import { CliError } from "../src/util/errors.js";
import { Session } from "../src/util/session.js";

let dir: string;
/** The `opts` the fake client's `requestRaw` last received. */
let lastOpts: { body?: unknown; timeoutMs?: number } | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tw-api-"));
  lastOpts = undefined;
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

/** A Session whose authed client is a stub that records the request `opts`. */
function makeSession(): Session {
  const store = new CredentialStore(join(dir, "credentials.json"));
  store.save({ user_id: "usr_1", access_token: "tok", expires_at: 9999999999 });
  const fakeClient = {
    requestRaw: async (
      _method: string,
      _path: string,
      opts: { body?: unknown; timeoutMs?: number },
    ): Promise<RawResponse> => {
      lastOpts = opts;
      return { ok: true, status: 200, text: "{}" };
    },
  } as unknown as ApiClient;
  return new Session({ store, clientFactory: () => fakeClient });
}

describe("tripwire api timeout", () => {
  it("defaults to the ~240s create read timeout (not the 10s default)", async () => {
    await runApi(makeSession(), "POST", "/canary", undefined, {});
    expect(lastOpts?.timeoutMs).toBe(CREATE_READ_TIMEOUT_MS);
  });

  it("honors a --timeout override in seconds", async () => {
    await runApi(makeSession(), "GET", "/canary", undefined, { timeout: "5" });
    expect(lastOpts?.timeoutMs).toBe(5000);
  });

  it("rejects an invalid --timeout", async () => {
    await expect(
      runApi(makeSession(), "GET", "/canary", undefined, { timeout: "abc" }),
    ).rejects.toBeInstanceOf(CliError);
    await expect(
      runApi(makeSession(), "GET", "/canary", undefined, { timeout: "-3" }),
    ).rejects.toBeInstanceOf(CliError);
  });
});
