import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../src/api/client.js";
import { runAuthStatus, runLogout } from "../src/commands/auth.js";
import { runList } from "../src/commands/canary.js";
import { CredentialStore, isExpired } from "../src/config/credentials.js";
import { buildProgram } from "../src/index.js";
import { CliError } from "../src/util/errors.js";
import { type Prompter, TtyPrompter } from "../src/util/prompt.js";
import { Session } from "../src/util/session.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tw-auth-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const NOW_MS = 1_800_000_000_000; // fixed clock; expires_at is epoch SECONDS
const FUTURE = 1_900_000_000; // seconds, after NOW_MS
const PAST = 1_700_000_000; // seconds, before NOW_MS

describe("isExpired", () => {
  it("is false for a token whose expiry is in the future", () => {
    expect(
      isExpired({ user_id: "usr_1", access_token: "tok", expires_at: FUTURE }, NOW_MS),
    ).toBe(false);
  });

  it("is true for a token whose expiry has passed", () => {
    expect(
      isExpired({ user_id: "usr_1", access_token: "tok", expires_at: PAST }, NOW_MS),
    ).toBe(true);
  });

  it("is true for a null/garbage expiry", () => {
    // A cache we cannot reason about means "log in again", never a crash. The
    // Python CLI shares this cache file and must agree; it used to raise here.
    const garbage = { user_id: "usr_1", access_token: "tok" } as unknown as Parameters<
      typeof isExpired
    >[0];
    expect(isExpired(garbage, NOW_MS)).toBe(true);
  });

  it.each([
    ["Infinity", Number.POSITIVE_INFINITY],
    ["NaN", Number.NaN],
    ["an unrenderable far-future value", 1e17],
  ])("is true for %s rather than trusting it as never-expiring", (_label, expires) => {
    expect(
      isExpired(
        { user_id: "usr_1", access_token: "tok", expires_at: expires as number },
        NOW_MS,
      ),
    ).toBe(true);
  });
});

describe("TtyPrompter.interactive", () => {
  // The guard that keeps the CLI from hanging on an invisible prompt in CI, in a
  // pipe, and inside the Claude Code plugin. Every other no-TTY test injects a
  // fake prompter, so without this one nothing would catch this returning `true`.
  it("is false when stdin is not a TTY", () => {
    const notATty = { isTTY: false } as unknown as NodeJS.ReadStream;
    expect(new TtyPrompter(notATty).interactive()).toBe(false);
  });

  it("is true when stdin is a TTY", () => {
    const aTty = { isTTY: true } as unknown as NodeJS.ReadStream;
    expect(new TtyPrompter(aTty).interactive()).toBe(true);
  });
});

describe("explicit `auth login` without a terminal", () => {
  // A sign-in that cannot happen must fail LOUDLY. The dangerous outcome is a
  // silent one: readline on a non-TTY stdin never settles, so `tripwire auth
  // login < /dev/null` printed "email:" and exited 0, reporting a login that
  // never happened as success to any script, CI job, or agent wrapping the CLI.
  // Auto-login is guarded by `interactive()`; the explicit command was not.
  it("fails with a nonzero exit instead of exiting 0 silently", async () => {
    const calls: string[] = [];
    const prompter = new FakePrompter([], false); // no TTY
    const { session } = makeSession(prompter, calls);

    await expect(session.login()).rejects.toThrow(CliError);
    await expect(session.login()).rejects.toThrow(/needs a terminal/);
    expect(calls).toEqual([]); // never even hits /auth/login/start
    expect(prompter.asked).toEqual([]);
  });
});

describe("credential cache validation", () => {
  it.each([
    ["a missing access_token", '{"user_id":"usr_1","expires_at":9999999999}'],
    ["a missing user_id", '{"access_token":"tok","expires_at":9999999999}'],
    ["an empty access_token", '{"user_id":"u","access_token":"","expires_at":9999999999}'],
    ["a JSON null", "null"],
    ["a JSON array", "[]"],
  ])("treats %s as not-logged-in rather than a usable session", (_label, contents) => {
    // Both CLIs share this file, so they must agree on what "logged in" means.
    // Node used to accept these partial caches and fire an unauthenticated
    // request, while Python rejected them and signed the user in.
    const path = join(dir, "credentials.json");
    writeFileSync(path, contents);
    expect(new CredentialStore(path).tryLoad()).toBeNull();
  });
});

describe("CredentialStore.tryLoad", () => {
  it("returns null when there is no cache file", () => {
    expect(new CredentialStore(join(dir, "nope.json")).tryLoad()).toBeNull();
  });

  it("returns null when the cache file is corrupt", () => {
    const path = join(dir, "credentials.json");
    // A half-written cache must mean "log in again", not a crash.
    writeFileSync(path, "{not json");
    expect(new CredentialStore(path).tryLoad()).toBeNull();
  });

  it("returns the credentials when the cache is valid", () => {
    const store = new CredentialStore(join(dir, "credentials.json"));
    store.save({ user_id: "usr_1", access_token: "tok", expires_at: FUTURE });
    expect(store.tryLoad()?.user_id).toBe("usr_1");
  });
});

/** A scripted prompter: answers come from `answers`, in order. */
class FakePrompter implements Prompter {
  readonly asked: string[] = [];
  readonly notices: string[] = [];
  private readonly answers: string[];

  constructor(
    answers: string[] = [],
    private readonly tty = true,
  ) {
    this.answers = [...answers];
  }

  interactive(): boolean {
    return this.tty;
  }

  async ask(question: string): Promise<string> {
    this.asked.push(question);
    const answer = this.answers.shift();
    if (answer === undefined) throw new Error(`unexpected prompt: ${question}`);
    return answer;
  }

  notify(line: string): void {
    this.notices.push(line);
  }
}

/** Records the API calls a command makes, and serves a successful login. */
function fakeClient(calls: string[]): ApiClient {
  return {
    loginStart: async () => {
      calls.push("loginStart");
    },
    loginWithCode: async () => {
      calls.push("loginWithCode");
      return { user_id: "usr_new", access_token: "tok_new", expires_at: FUTURE };
    },
    listCanaries: async () => {
      calls.push("listCanaries");
      return { canaries: [] };
    },
  } as unknown as ApiClient;
}

function makeSession(
  prompter: Prompter,
  calls: string[],
): { session: Session; store: CredentialStore } {
  const store = new CredentialStore(join(dir, "credentials.json"));
  const session = new Session({
    store,
    prompter,
    clientFactory: () => fakeClient(calls),
  });
  return { session, store };
}

describe("automatic login", () => {
  it("signs the user in, then runs the command they actually asked for", async () => {
    const calls: string[] = [];
    const prompter = new FakePrompter(["me@co.com", "123456"]);
    const { session, store } = makeSession(prompter, calls);

    await runList(session, { json: true });

    expect(calls).toEqual(["loginStart", "loginWithCode", "listCanaries"]);
    expect(prompter.asked).toEqual(["email", "code"]);
    expect(prompter.notices[0]).toContain("not logged in");
    // The token is cached, so the next command will not prompt again.
    expect(store.tryLoad()?.user_id).toBe("usr_new");
  });

  it("re-signs-in when the cached token has expired", async () => {
    const calls: string[] = [];
    const prompter = new FakePrompter(["me@co.com", "123456"]);
    const { session, store } = makeSession(prompter, calls);
    store.save({ user_id: "usr_old", access_token: "stale", expires_at: PAST });

    await runList(session, { json: true });

    expect(calls).toEqual(["loginStart", "loginWithCode", "listCanaries"]);
    expect(prompter.notices[0]).toContain("expired");
    expect(store.tryLoad()?.user_id).toBe("usr_new");
  });

  it("uses the cached token without prompting when it is still valid", async () => {
    const calls: string[] = [];
    const prompter = new FakePrompter([]);
    const { session, store } = makeSession(prompter, calls);
    store.save({ user_id: "usr_1", access_token: "tok", expires_at: FUTURE });

    await runList(session, { json: true });

    expect(calls).toEqual(["listCanaries"]);
    expect(prompter.asked).toEqual([]);
  });

  it("fails fast without prompting or calling the API when stdin is not a TTY", async () => {
    const calls: string[] = [];
    const prompter = new FakePrompter([], false);
    const { session } = makeSession(prompter, calls);

    await expect(runList(session, { json: true })).rejects.toThrow(/tripwire auth login/);
    expect(calls).toEqual([]);
    expect(prompter.asked).toEqual([]);
  });
});

describe("auth status", () => {
  it("prints the identity and the expiry, and never prompts", () => {
    const calls: string[] = [];
    const prompter = new FakePrompter([]);
    const { session, store } = makeSession(prompter, calls);
    store.save({
      user_id: "usr_1",
      access_token: "tok",
      expires_at: FUTURE,
      email: "me@co.com",
    });
    const lines: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      lines.push(String(chunk));
      return true;
    });

    runAuthStatus(session);
    spy.mockRestore();

    expect(lines.join("")).toContain("usr_1");
    expect(lines.join("")).toContain("me@co.com");
    expect(lines.join("")).toContain("session: valid until");
    expect(prompter.asked).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("errors (never prompts) when logged out", () => {
    const prompter = new FakePrompter([]);
    const { session } = makeSession(prompter, []);
    expect(() => runAuthStatus(session)).toThrow(CliError);
    expect(() => runAuthStatus(session)).toThrow(/tripwire auth login/);
    expect(prompter.asked).toEqual([]);
  });
});

describe("auth logout", () => {
  it("never prompts, even when logged out", () => {
    const prompter = new FakePrompter([], false);
    const { session } = makeSession(prompter, []);
    const spy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    runLogout(session);
    spy.mockRestore();
    expect(prompter.asked).toEqual([]);
  });
});

describe("command surface", () => {
  it("exposes auth login/logout/status and no top-level login", () => {
    const program = buildProgram(new Session());
    const auth = program.commands.find((c) => c.name() === "auth");
    expect(auth?.commands.map((c) => c.name()).sort()).toEqual(["login", "logout", "status"]);
    // `status` stays top-level: it is the fired-canary dashboard, not auth state.
    expect(program.commands.find((c) => c.name() === "status")).toBeDefined();
  });

  it("`tripwire login` fails with a migration hint and is hidden from help", async () => {
    const program = buildProgram(new Session());
    const lines: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      lines.push(String(chunk));
      return true;
    });

    await program.parseAsync(["node", "tripwire", "login"]);
    spy.mockRestore();
    process.exitCode = 0; // `action()` sets 1; do not leak it into the test run.

    expect(lines.join("")).toContain("`tripwire login` moved to `tripwire auth login`");
    expect(program.helpInformation()).not.toContain("\n  login");
  });
});
