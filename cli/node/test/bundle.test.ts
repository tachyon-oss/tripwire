import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Command } from "commander";
import { strToU8, zipSync } from "fflate";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiClient } from "../src/api/client.js";
import { ApiError } from "../src/api/errors.js";
import {
  downloadWithRetry,
  extractZip,
  filenameFromDisposition,
  runBundleCreate,
  runBundleDownload,
  runBundleShow,
} from "../src/commands/bundle.js";
import { CredentialStore, NoCredentialsError } from "../src/config/credentials.js";
import { buildProgram, Session } from "../src/index.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tw-bundle-"));
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

/** A real zip fixture: a top-level file and a nested one. */
const FIXTURE_ZIP = zipSync({
  "README.md": strToU8("hello\n"),
  "src/app.py": strToU8("print(1)\n"),
});

/** A fake `fetch` returning a binary zip download with a Content-Disposition. */
function zipFetch(filename = "bundle.zip", bytes: Uint8Array = FIXTURE_ZIP): typeof fetch {
  return (async () =>
    ({
      ok: true,
      status: 200,
      headers: new Headers({
        "content-type": "application/zip",
        "content-disposition": `attachment; filename="${filename}"`,
      }),
      arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      text: async () => "",
    }) as unknown as Response) as typeof fetch;
}

/** A fake `fetch` returning a JSON error with the given status + detail. */
function errorFetch(status: number, detail: string): typeof fetch {
  return (async () =>
    ({
      ok: false,
      status,
      headers: new Headers(),
      text: async () => JSON.stringify({ detail }),
      arrayBuffer: async () => new ArrayBuffer(0),
    }) as unknown as Response) as typeof fetch;
}

interface RecordedCall {
  method: string;
  url: string;
  body: Record<string, unknown> | undefined;
}

/**
 * A fake `fetch` that routes the two bundle POSTs: `POST /bundles` returns a
 * create result, `POST /bundles/{id}` returns the zip. Records every call.
 */
function routingFetch(createId = "b_auto"): {
  fetchImpl: typeof fetch;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const raw = init?.body;
    const body = typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
    const target = String(url);
    calls.push({ method, url: target, body });
    if (method === "POST" && /\/bundles$/.test(target)) {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        text: async () =>
          JSON.stringify({ status: "ready", bundle_id: createId, expires_at: "2026-01-01T00:00:00Z" }),
        arrayBuffer: async () => new ArrayBuffer(0),
      } as unknown as Response;
    }
    if (method === "POST" && /\/bundles\/[^/]+$/.test(target)) {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ "content-disposition": 'attachment; filename="ledgerflow.zip"' }),
        arrayBuffer: async () =>
          FIXTURE_ZIP.buffer.slice(
            FIXTURE_ZIP.byteOffset,
            FIXTURE_ZIP.byteOffset + FIXTURE_ZIP.byteLength,
          ),
        text: async () => "",
      } as unknown as Response;
    }
    return { ok: false, status: 404, headers: new Headers(), text: async () => "{}" } as unknown as Response;
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function makeSession(fetchImpl: typeof fetch, opts: { loggedIn?: boolean } = {}): Session {
  const store = new CredentialStore(join(dir, "credentials.json"));
  if (opts.loggedIn !== false) {
    store.save({ user_id: "usr_1", access_token: "tok", expires_at: 9999999999 });
  }
  return new Session({
    store,
    clientFactory: (baseUrl, token) =>
      new ApiClient({ baseUrl, token: token ?? null, fetchImpl }),
  });
}

/** Silence the stderr summary lines so test output stays clean. */
function muteStderr(): void {
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
}

describe("filenameFromDisposition", () => {
  it("parses a quoted filename", () => {
    expect(filenameFromDisposition('attachment; filename="bundle.zip"')).toBe("bundle.zip");
  });
  it("parses an unquoted filename", () => {
    expect(filenameFromDisposition("attachment; filename=ledgerflow.zip")).toBe(
      "ledgerflow.zip",
    );
  });
  it("prefers the RFC 5987 extended filename*", () => {
    expect(
      filenameFromDisposition("attachment; filename=\"a.zip\"; filename*=UTF-8''b%20c.zip"),
    ).toBe("b c.zip");
  });
  it("strips any path components (no traversal)", () => {
    expect(filenameFromDisposition('attachment; filename="../../etc/passwd"')).toBe("passwd");
  });
  it("returns null when absent", () => {
    expect(filenameFromDisposition(null)).toBeNull();
    expect(filenameFromDisposition("inline")).toBeNull();
  });

  it("does not crash on a malformed filename* (URIError) — returns null", () => {
    const malformed = "attachment; filename*=UTF-8''%E0%A4%A";
    expect(() => filenameFromDisposition(malformed)).not.toThrow();
    expect(filenameFromDisposition(malformed)).toBeNull();
  });

  it("falls back to the plain filename when filename* is malformed", () => {
    expect(
      filenameFromDisposition("attachment; filename=\"ok.zip\"; filename*=UTF-8''%ZZ"),
    ).toBe("ok.zip");
  });
});

describe("extractZip (zip-slip guard)", () => {
  it("extracts safe entries and creates intermediate dirs", () => {
    const target = join(dir, "out");
    const { written, skipped } = extractZip(FIXTURE_ZIP, target);
    expect(written).toBe(2);
    expect(skipped).toEqual([]);
    expect(readFileSync(join(target, "README.md"), "utf8")).toBe("hello\n");
    expect(readFileSync(join(target, "src", "app.py"), "utf8")).toBe("print(1)\n");
  });

  it("skips an entry that escapes the target dir via ..", () => {
    const evil = zipSync({
      "safe.txt": strToU8("ok"),
      "../evil.txt": strToU8("pwned"),
    });
    const target = join(dir, "out");
    mkdirSync(target, { recursive: true });
    const { written, skipped } = extractZip(evil, target);
    expect(readFileSync(join(target, "safe.txt"), "utf8")).toBe("ok");
    // The traversal target (a sibling of `out`) must NOT have been written.
    expect(existsSync(join(dir, "evil.txt"))).toBe(false);
    expect(skipped).toContain("../evil.txt");
    expect(written).toBe(1);
  });

  it("skips an absolute-path entry", () => {
    const evil = zipSync({ "/etc/pwned": strToU8("x"), "ok.txt": strToU8("y") });
    const target = join(dir, "out2");
    const { written, skipped } = extractZip(evil, target);
    expect(written).toBe(1);
    expect(skipped).toContain("/etc/pwned");
  });
});

describe("runBundleDownload — default (extract)", () => {
  it("extracts into -o <dir>", async () => {
    muteStderr();
    const target = join(dir, "extracted");
    await runBundleDownload(makeSession(zipFetch()), "b1", { output: target });
    expect(readFileSync(join(target, "README.md"), "utf8")).toBe("hello\n");
    expect(readFileSync(join(target, "src", "app.py"), "utf8")).toBe("print(1)\n");
  });

  it("extracts into ./<name>/ derived from the disposition filename", async () => {
    muteStderr();
    const prev = process.cwd();
    process.chdir(dir);
    try {
      await runBundleDownload(makeSession(zipFetch("ledgerflow.zip")), "b1", {});
      expect(readFileSync(join(dir, "ledgerflow", "README.md"), "utf8")).toBe("hello\n");
    } finally {
      process.chdir(prev);
    }
  });

  it("refuses to extract into a non-empty directory", async () => {
    const target = join(dir, "busy");
    mkdirSync(target);
    writeFileSync(join(target, "pre.txt"), "keep");
    await expect(
      runBundleDownload(makeSession(zipFetch()), "b1", { output: target }),
    ).rejects.toThrow(/already exists and is not empty/);
    // The pre-existing file is untouched (no clobber).
    expect(readFileSync(join(target, "pre.txt"), "utf8")).toBe("keep");
  });

  it("-o <dir> extracts files DIRECTLY into <dir>, not <dir>/<name>/", async () => {
    muteStderr();
    const { fetchImpl } = routingFetch();
    const target = join(dir, "flat");
    await runBundleDownload(makeSession(fetchImpl), "b_given", { output: target });
    expect(existsSync(join(target, "README.md"))).toBe(true); // top-level
    expect(existsSync(join(target, "src", "app.py"))).toBe(true);
    // NOT nested under a <name> subdirectory.
    expect(existsSync(join(target, "ledgerflow", "README.md"))).toBe(false);
  });
});

describe("runBundleDownload — no id (auto-create then download)", () => {
  it("creates a bundle for the operator, then downloads + extracts it", async () => {
    muteStderr();
    const { fetchImpl, calls } = routingFetch("b_auto");
    const target = join(dir, "kit");
    await runBundleDownload(makeSession(fetchImpl), undefined, { output: target });

    const posts = calls.filter((c) => c.method === "POST");
    // First POST is the create (…/bundles), then the download of the new id.
    expect(posts[0]?.url).toMatch(/\/bundles$/);
    expect(posts.some((c) => /\/bundles\/b_auto$/.test(c.url))).toBe(true);
    // The created bundle was extracted.
    expect(readFileSync(join(target, "README.md"), "utf8")).toBe("hello\n");
  });

  it("with an id given: downloads that id and does NOT create", async () => {
    muteStderr();
    const { fetchImpl, calls } = routingFetch();
    const target = join(dir, "kit2");
    await runBundleDownload(makeSession(fetchImpl), "b_given", { output: target });

    expect(calls.some((c) => c.method === "POST" && /\/bundles$/.test(c.url))).toBe(false);
    expect(calls.some((c) => /\/bundles\/b_given$/.test(c.url))).toBe(true);
    expect(readFileSync(join(target, "README.md"), "utf8")).toBe("hello\n");
  });

  it("sends an EMPTY create body in the no-id path (no template_id/email/turnstile)", async () => {
    muteStderr();
    const { fetchImpl, calls } = routingFetch();
    await runBundleDownload(makeSession(fetchImpl), undefined, { output: join(dir, "a") });
    const create = calls.find((c) => c.method === "POST" && /\/bundles$/.test(c.url));
    expect(create?.body).toEqual({});
  });
});

describe("runBundleDownload — --zip (keep archive)", () => {
  it("saves the raw archive to -o <file>", async () => {
    muteStderr();
    const target = join(dir, "keep.zip");
    await runBundleDownload(makeSession(zipFetch()), "b1", { zip: true, output: target });
    expect(readFileSync(target)).toEqual(Buffer.from(FIXTURE_ZIP));
    // Not extracted.
    expect(existsSync(join(dir, "README.md"))).toBe(false);
  });

  it("saves <name>.zip in cwd when no -o is given", async () => {
    muteStderr();
    const prev = process.cwd();
    process.chdir(dir);
    try {
      await runBundleDownload(makeSession(zipFetch("ledgerflow.zip")), "b1", { zip: true });
      expect(readFileSync(join(dir, "ledgerflow.zip"))).toEqual(Buffer.from(FIXTURE_ZIP));
    } finally {
      process.chdir(prev);
    }
  });

  it("refuses to clobber an existing output file", async () => {
    muteStderr();
    const target = join(dir, "exists.zip");
    writeFileSync(target, "old-archive");
    await expect(
      runBundleDownload(makeSession(zipFetch()), "b1", { zip: true, output: target }),
    ).rejects.toThrow(/already exists/);
    // The pre-existing file is untouched.
    expect(readFileSync(target, "utf8")).toBe("old-archive");
  });
});

describe("runBundleDownload — -o - (stream)", () => {
  it("streams raw zip bytes to stdout and writes nothing to disk", async () => {
    muteStderr();
    let captured: Buffer | undefined;
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      if (typeof chunk !== "string") captured = Buffer.from(chunk);
      return true;
    });
    await runBundleDownload(makeSession(zipFetch()), "b1", { output: "-" });
    expect(captured).toEqual(Buffer.from(FIXTURE_ZIP));
    expect(existsSync(join(dir, "bundle"))).toBe(false);
  });
});

describe("downloadWithRetry (409 bundle_preparing)", () => {
  it("retries while preparing, then succeeds", async () => {
    const preparing = new ApiError(409, "bundle_preparing");
    const client = {
      downloadBundle: vi
        .fn()
        .mockRejectedValueOnce(preparing)
        .mockRejectedValueOnce(preparing)
        .mockResolvedValue({ headers: new Headers(), buffer: Buffer.from(FIXTURE_ZIP) }),
    };
    const sleep = vi.fn(async () => {});
    const result = await downloadWithRetry(client, "b1", { sleep });
    expect(client.downloadBundle).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(result.buffer).toEqual(Buffer.from(FIXTURE_ZIP));
  });

  it("gives up after exhausting attempts, surfacing the 409", async () => {
    const client = {
      downloadBundle: vi.fn().mockRejectedValue(new ApiError(409, "bundle_preparing")),
    };
    const sleep = vi.fn(async () => {});
    await expect(downloadWithRetry(client, "b1", { attempts: 3, sleep })).rejects.toMatchObject({
      status: 409,
      detail: "bundle_preparing",
    });
    expect(client.downloadBundle).toHaveBeenCalledTimes(3);
  });

  it("propagates a non-409 error immediately without retrying", async () => {
    const client = {
      downloadBundle: vi.fn().mockRejectedValue(new ApiError(404, "bundle_not_found")),
    };
    const sleep = vi.fn(async () => {});
    await expect(downloadWithRetry(client, "b1", { sleep })).rejects.toMatchObject({
      status: 404,
    });
    expect(client.downloadBundle).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
  });
});

describe("bundle error mapping", () => {
  it("maps a 404 to a clear not-found message", async () => {
    await expect(
      runBundleShow(makeSession(errorFetch(404, "bundle_not_found")), "b1", {}),
    ).rejects.toThrow(/bundle not found/);
  });

  it("maps a 410 to a clear revoked/expired message", async () => {
    await expect(
      runBundleShow(makeSession(errorFetch(410, "revoked")), "b1", {}),
    ).rejects.toThrow(/revoked/);
  });

  it("does not recommend a nonexistent flag when browser verification is required", async () => {
    await expect(
      runBundleCreate(makeSession(errorFetch(400, "challenge_failed"))),
    ).rejects.toThrow(
      "bundle creation requires browser verification; download it from https://tripwire.so.",
    );
  });

  it("reports a genuine network failure as a network error, NOT bundle-not-found", async () => {
    const netFail: typeof fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    await expect(runBundleShow(makeSession(netFail), "b1", {})).rejects.toThrow(/cannot reach/);
    await expect(runBundleShow(makeSession(netFail), "b1", {})).rejects.not.toThrow(
      /bundle not found/,
    );
  });
});

describe("bundle commands require login", () => {
  it("throws NoCredentialsError before making any request", async () => {
    const fetchSpy = vi.fn();
    const session = makeSession(fetchSpy as unknown as typeof fetch, { loggedIn: false });
    await expect(runBundleShow(session, "b1", {})).rejects.toBeInstanceOf(NoCredentialsError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("bundle command wiring", () => {
  function bundleGroup(): Command {
    const group = buildProgram(new Session()).commands.find((c) => c.name() === "bundle");
    if (!group) throw new Error("bundle group missing");
    return group;
  }

  it("registers the four bundle subcommands", () => {
    const names = bundleGroup()
      .commands.map((c) => c.name())
      .sort();
    expect(names).toEqual(["contents", "create", "download", "show"]);
  });

  it("download takes -o/--output and --zip, an OPTIONAL id, and NO --template", () => {
    const download = bundleGroup().commands.find((c) => c.name() === "download");
    const longs = download?.options.map((o) => o.long) ?? [];
    expect(longs).toContain("--output");
    expect(longs).toContain("--zip");
    expect(longs).not.toContain("--template");
    // The `id` positional is optional (bare `bundle download` auto-creates).
    expect(download?.registeredArguments.map((a) => a.required)).toEqual([false]);
  });

  it("create exposes no user-facing options (no --email/--turnstile-token/--template)", () => {
    const create = bundleGroup().commands.find((c) => c.name() === "create");
    const longs = (create?.options.map((o) => o.long) ?? []).filter((l) => l !== "--help");
    expect(longs).toEqual([]);
  });
});

describe("runBundleCreate request body", () => {
  /** A fake `fetch` that records the POSTed JSON body and returns a create result. */
  function createFetch(): { fetchImpl: typeof fetch; body: () => Record<string, unknown> | undefined } {
    let captured: Record<string, unknown> | undefined;
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      const raw = init?.body;
      captured = typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        text: async () =>
          JSON.stringify({ status: "ready", bundle_id: "b_new", expires_at: "2026-01-01T00:00:00Z" }),
        arrayBuffer: async () => new ArrayBuffer(0),
      } as unknown as Response;
    }) as typeof fetch;
    return { fetchImpl, body: () => captured };
  }

  it("sends an EMPTY body — no email, turnstile_token, or template_id", async () => {
    muteStderr();
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const { fetchImpl, body } = createFetch();
    await runBundleCreate(makeSession(fetchImpl));
    expect(body()).toEqual({});
  });
});
