import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiClient } from "../src/api/client.js";
import { CredentialStore } from "../src/config/credentials.js";
import { buildProgram, Session } from "../src/index.js";

// Toggle to make `chmodSync` throw while `writeFileSync` still succeeds, so we
// can exercise the chmod-only-failure branch of writeJsonReveal. node:fs exports
// are non-configurable (cannot be spied), so mock the module with a passthrough.
const state = vi.hoisted(() => ({ failChmod: false }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    chmodSync: (path: string, mode: number) => {
      if (state.failChmod) throw new Error("EPERM: operation not permitted");
      return actual.chmodSync(path, mode);
    },
  };
});

let dir: string;
let stdout: string;
let stderr: string;

/** A fake `fetch` returning `obj` as the create (201) JSON response. */
function jsonFetch(obj: unknown): typeof fetch {
  return (async () =>
    ({
      ok: true,
      status: 201,
      headers: new Headers(),
      text: async () => JSON.stringify(obj),
      arrayBuffer: async () => new ArrayBuffer(0),
    }) as unknown as Response) as typeof fetch;
}

function makeSession(fetchImpl: typeof fetch): Session {
  const store = new CredentialStore(join(dir, "credentials.json"));
  store.save({ user_id: "usr_1", access_token: "tok", expires_at: 9999999999 });
  return new Session({
    store,
    clientFactory: (baseUrl, token) => new ApiClient({ baseUrl, token: token ?? null, fetchImpl }),
  });
}

async function run(session: Session, ...argv: string[]): Promise<void> {
  await buildProgram(session).parseAsync(["node", "tripwire", ...argv]);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tw-reveal-"));
  stdout = "";
  stderr = "";
  state.failChmod = false;
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  state.failChmod = false;
  rmSync(dir, { recursive: true, force: true });
  process.exitCode = 0;
});

describe("H1: placement create with missing credential fields", () => {
  it("dumps the raw create JSON to stdout and errors (never drops the minted secret)", async () => {
    // A 2xx response that is missing access_key_id / secret_access_key.
    const resp = { id: "tw_x", type: "aws_access_key", status: "active", region: "us-east-1" };
    await run(makeSession(jsonFetch(resp)), "canary", "create", "aws.profile");

    expect(process.exitCode).toBe(1);
    // The raw response landed on stdout so the one-time secret isn't lost.
    expect(stdout).toContain('"id": "tw_x"');
    expect(stdout).toContain('"type": "aws_access_key"');
    expect(stderr).toContain("could not render the block");
  });
});

describe("H3: writeJsonReveal separates the write from the chmod", () => {
  const AWS = {
    id: "tw_a",
    type: "aws_access_key",
    status: "active",
    access_key_id: "AKIA",
    secret_access_key: "SEK",
    region: "us-east-1",
  };

  it("writes the JSON at mode 0600 on the happy path (nothing on stdout)", async () => {
    const target = join(dir, "cred.json");
    await run(makeSession(jsonFetch(AWS)), "canary", "create", "aws.access_key", "-o", target);

    expect(stdout).toBe("");
    expect((JSON.parse(readFileSync(target, "utf8")) as { access_key_id: string }).access_key_id).toBe("AKIA");
    expect(statSync(target).mode & 0o777).toBe(0o600);
    expect(stderr).toContain(`wrote ${target}`);
  });

  it("on chmod-only failure: keeps the written file, warns, does NOT re-dump the secret", async () => {
    state.failChmod = true;
    const target = join(dir, "cred2.json");
    await run(makeSession(jsonFetch(AWS)), "canary", "create", "aws.access_key", "-o", target);

    // The file was written (the write itself succeeded).
    expect(existsSync(target)).toBe(true);
    expect((JSON.parse(readFileSync(target, "utf8")) as { secret_access_key: string }).secret_access_key).toBe("SEK");
    // The secret is NOT re-dumped to stdout (it is already safely on disk).
    expect(stdout).toBe("");
    expect(stderr).toContain("could not set mode 0600");
  });
});
