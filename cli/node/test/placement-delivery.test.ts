import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiClient } from "../src/api/client.js";
import { CredentialStore } from "../src/config/credentials.js";
import { buildProgram } from "../src/index.js";
import { Session } from "../src/util/session.js";

/**
 * End-to-end (offline) exercise of the placement create path through the real
 * commander program, with the network faked at the `fetch` boundary. The
 * contract: ONLY the rendered block on stdout on the default path (nothing on
 * stderr), plus the `-o` writer. The profile name comes from the backend
 * response (`name`).
 */

const AWS_RESPONSE = {
  id: "tw_abc123",
  type: "aws_access_key",
  status: "active",
  name: "acme-prod",
  access_key_id: "AKIAEXAMPLE",
  secret_access_key: "wJalrEXAMPLEKEY",
  region: "us-east-1",
};

let dir: string;
let stdout: string;
let stderr: string;
let lastRequestBody: unknown;

const fakeFetch: typeof fetch = async (_url, init) => {
  const raw = (init as RequestInit | undefined)?.body;
  lastRequestBody = typeof raw === "string" ? JSON.parse(raw) : raw;
  return {
    ok: true,
    status: 201,
    text: async () => JSON.stringify(AWS_RESPONSE),
  } as unknown as Response;
};

function makeSession(): Session {
  const store = new CredentialStore(join(dir, "credentials.json"));
  store.save({ user_id: "usr_1", access_token: "tok", expires_at: 9999999999 });
  return new Session({
    store,
    clientFactory: (baseUrl, token) =>
      new ApiClient({ baseUrl, token: token ?? null, fetchImpl: fakeFetch }),
  });
}

async function run(...argv: string[]): Promise<void> {
  await buildProgram(makeSession()).parseAsync(["node", "tripwire", ...argv]);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tw-deliver-"));
  lastRequestBody = undefined;
  stdout = "";
  stderr = "";
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
  rmSync(dir, { recursive: true, force: true });
  process.exitCode = 0;
});

describe("aws.profile placement — default (stdout) delivery", () => {
  it("POSTs the snake wire type (dotted → snake translation preserved)", async () => {
    await run("canary", "create", "aws.profile");
    expect((lastRequestBody as { type?: string }).type).toBe("aws_access_key");
  });

  it("prints ONLY the block (backend-named) to stdout, and nothing to stderr", async () => {
    await run("canary", "create", "aws.profile");
    expect(stdout).toBe(
      "\n[profile acme-prod]\n" +
        "aws_access_key_id = AKIAEXAMPLE\n" +
        "aws_secret_access_key = wJalrEXAMPLEKEY\n" +
        "region = us-east-1\n",
    );
    expect(stderr).toBe("");
  });
});

describe("aws.credentials placement — bare header, no region", () => {
  it("renders a [<name>] block without a region line", async () => {
    await run("canary", "create", "aws.credentials");
    expect(stdout).toBe(
      "\n[acme-prod]\n" +
        "aws_access_key_id = AKIAEXAMPLE\n" +
        "aws_secret_access_key = wJalrEXAMPLEKEY\n",
    );
    expect(stdout).not.toContain("region");
  });
});

describe("aws.profile placement — -o file delivery", () => {
  it("writes the block to the file and keeps stdout empty", async () => {
    const target = join(dir, "config");
    await run("canary", "create", "aws.profile", "-o", target);
    expect(stdout).toBe("");
    expect(readFileSync(target, "utf8")).toBe(
      "[profile acme-prod]\n" +
        "aws_access_key_id = AKIAEXAMPLE\n" +
        "aws_secret_access_key = wJalrEXAMPLEKEY\n" +
        "region = us-east-1\n",
    );
    expect(stderr).toContain(target);
  });

  it("appends to an existing file with a separator (no fuse, no dedup)", async () => {
    const target = join(dir, "config");
    writeFileSync(target, "[profile existing]\naws_access_key_id = OLD\n");
    await run("canary", "create", "aws.profile", "-o", target);
    const contents = readFileSync(target, "utf8");
    expect(contents).toContain("[profile existing]");
    expect(contents).toContain("\n\n[profile acme-prod]\n");
    expect(stdout).toBe("");
  });
});
