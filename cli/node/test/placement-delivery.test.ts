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
 * commander program, with the network faked at the `fetch` boundary. This is the
 * critical delivery contract: the rendered block on stdout, everything else on
 * stderr, and the `-o` writer.
 */

const AWS_RESPONSE = {
  id: "tw_abc123",
  type: "aws_access_key",
  status: "active",
  access_key_id: "AKIAEXAMPLE",
  secret_access_key: "wJalrEXAMPLEKEY",
  region: "us-east-1",
};

let dir: string;
let stdout: string;
let stderr: string;
let lastRequestBody: unknown;

/** A fake `fetch` that records the request body and returns the canned response. */
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
    await run("canary", "create", "aws.profile", "--name", "prod-deploy");
    expect((lastRequestBody as { type?: string }).type).toBe("aws_access_key");
  });

  it("prints ONLY the block to stdout, with a leading and trailing newline", async () => {
    await run("canary", "create", "aws.profile", "--name", "prod-deploy");
    expect(stdout).toBe(
      "\n[profile prod-deploy]\n" +
        "aws_access_key_id = AKIAEXAMPLE\n" +
        "aws_secret_access_key = wJalrEXAMPLEKEY\n" +
        "region = us-east-1\n",
    );
  });

  it("sends all reporting to stderr, never the credential block", async () => {
    await run("canary", "create", "aws.profile", "--name", "prod-deploy");
    expect(stderr).toContain("tw_abc123");
    expect(stderr).toContain("(via aws.profile)");
    expect(stderr).toContain("name: prod-deploy");
    // The block must NOT leak onto stderr.
    expect(stderr).not.toContain("[profile prod-deploy]");
    expect(stderr).not.toContain("aws_secret_access_key");
  });
});

describe("aws.credentials placement — bare header, no region", () => {
  it("renders a [<name>] block without a region line", async () => {
    await run("canary", "create", "aws.credentials", "--name", "s3-sync");
    expect(stdout).toBe(
      "\n[s3-sync]\n" +
        "aws_access_key_id = AKIAEXAMPLE\n" +
        "aws_secret_access_key = wJalrEXAMPLEKEY\n",
    );
    expect(stdout).not.toContain("region");
  });
});

describe("aws.profile placement — -o file delivery", () => {
  it("writes the block to the file and keeps stdout empty", async () => {
    const target = join(dir, "config");
    await run("canary", "create", "aws.profile", "--name", "prod-deploy", "-o", target);
    expect(stdout).toBe("");
    expect(readFileSync(target, "utf8")).toBe(
      "[profile prod-deploy]\n" +
        "aws_access_key_id = AKIAEXAMPLE\n" +
        "aws_secret_access_key = wJalrEXAMPLEKEY\n" +
        "region = us-east-1\n",
    );
    expect(stderr).toContain(`wrote [profile prod-deploy] to ${target}`);
  });

  it("appends to an existing file with a separator (no fuse, no dedup)", async () => {
    const target = join(dir, "config");
    writeFileSync(target, "[profile existing]\naws_access_key_id = OLD\n");
    await run("canary", "create", "aws.profile", "--name", "prod-deploy", "-o", target);
    const contents = readFileSync(target, "utf8");
    expect(contents).toContain("[profile existing]");
    expect(contents).toContain("\n\n[profile prod-deploy]\n");
    expect(stdout).toBe("");
  });
});

describe("aws placement — OPSEC name gate blocks the mint", () => {
  it("rejects a banned --name before any credential is created", async () => {
    await run("canary", "create", "aws.profile", "--name", "prod-honeypot");
    expect(process.exitCode).toBe(1);
    expect(stdout).toBe("");
    expect(stderr).toContain('contains the banned term "honeypot"');
  });
});
