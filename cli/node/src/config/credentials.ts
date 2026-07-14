/**
 * Local credential cache for the Tripwire CLI.
 *
 * The token and identity are kept in a single JSON file, by default
 * `~/.config/tripwire/credentials.json` (honoring `XDG_CONFIG_HOME`). This is
 * the SAME file and SAME shape the Python CLI reads/writes
 * (`cli/python/tripwire_cli/credentials.py`), so a `login` from either
 * CLI is honored by the other. The server URL is stored only when it differs
 * from the public default, so a normal user's cache is just their token and
 * identity.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/**
 * The public Tripwire API. A cache targeting this server omits the `server`
 * field entirely; only self-hosted / test targets are written.
 */
export const DEFAULT_SERVER = "https://tripwire.so/api/v1";

export interface Credentials {
  user_id: string;
  access_token: string;
  expires_at: number;
  /** Stored only for non-default servers; absent means the public default. */
  server?: string | null;
  /** Present for email-code logins; absent for caches written by older CLIs. */
  email?: string | null;
}

export class NoCredentialsError extends Error {
  constructor(message = "not logged in (run `tripwire auth login`)") {
    super(message);
    this.name = "NoCredentialsError";
  }
}

/**
 * An expiry at or beyond this is not a token, it is a corrupt cache: past the
 * year 9999 the date cannot even be rendered. Treating it as expired means the
 * user logs in again, instead of us trusting a garbage value as never-expiring.
 */
const MAX_EXPIRY_SECONDS = 253_402_300_800; // 9999-12-31T00:00:00Z

/**
 * Whether a cached token has passed its expiry. `expires_at` is epoch seconds.
 * Anything we cannot reason about (missing, non-numeric, NaN, Infinity, or an
 * unrenderable far-future value) counts as expired: a cache we do not
 * understand means "log in again", never a crash and never blind trust. The
 * Python CLI shares this file and applies the same rule.
 */
export function isExpired(creds: Credentials, nowMs: number = Date.now()): boolean {
  const expiresAt = creds.expires_at;
  if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) return true;
  if (expiresAt >= MAX_EXPIRY_SECONDS) return true;
  return expiresAt * 1000 <= nowMs;
}

/** The effective API base URL: the stored server, or the public default. */
export function resolvedServer(creds: Credentials): string {
  return creds.server || DEFAULT_SERVER;
}

export function defaultPath(): string {
  const base = process.env["XDG_CONFIG_HOME"] || join(homedir(), ".config");
  return join(base, "tripwire", "credentials.json");
}

/** The set of fields this CLI persists, in the shape the Python CLI expects. */
const KNOWN_FIELDS = ["user_id", "access_token", "expires_at", "server", "email"] as const;

export class CredentialStore {
  readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  load(): Credentials {
    if (!existsSync(this.path)) {
      throw new NoCredentialsError();
    }
    const data = JSON.parse(readFileSync(this.path, "utf8")) as unknown;
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new NoCredentialsError();
    }
    // Forward-compatible: keep only the fields this CLI knows about, so an older
    // CLI reading a cache written by a newer one does not choke on an unexpected
    // key. Also drops the legacy `role` field.
    const source = data as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of KNOWN_FIELDS) {
      if (key in source) out[key] = source[key];
    }
    // A cache without a usable identity and token is not a session. This mirrors
    // the validation the login path already does before writing, and matches the
    // Python CLI, which rejects the same file (its dataclass requires both). Two
    // clients sharing one cache file must agree on what "logged in" means.
    if (
      typeof out["user_id"] !== "string" ||
      out["user_id"] === "" ||
      typeof out["access_token"] !== "string" ||
      out["access_token"] === ""
    ) {
      throw new NoCredentialsError();
    }
    return out as unknown as Credentials;
  }

  /**
   * The cached credentials, or `null` when there is no usable cache. A missing,
   * unreadable, or corrupt file all mean the same thing to a caller: log in again.
   */
  tryLoad(): Credentials | null {
    try {
      return this.load();
    } catch {
      return null;
    }
  }

  save(creds: Credentials): string {
    mkdirSync(dirname(this.path), { recursive: true });
    // Omit optional fields that are unset (`server` for the default target,
    // `email` when absent) so the file carries only what it needs — matching the
    // Python writer byte-for-byte in the common case.
    const data: Record<string, unknown> = {};
    const source = creds as unknown as Record<string, unknown>;
    for (const key of KNOWN_FIELDS) {
      const value = source[key];
      if (value !== undefined && value !== null) data[key] = value;
    }
    writeFileSync(this.path, JSON.stringify(data, null, 2), { mode: 0o600 });
    return this.path;
  }

  clear(): boolean {
    if (!existsSync(this.path)) return false;
    rmSync(this.path);
    return true;
  }

  cachedServer(): string | null {
    try {
      return this.load().server ?? null;
    } catch {
      return null;
    }
  }
}

export function defaultStore(): CredentialStore {
  return new CredentialStore(defaultPath());
}

/**
 * Server URL for `login`: the `TRIPWIRE_SERVER` env override, else the last-used
 * cached server, else the default. (Matches the Python `resolve_login_server`;
 * env only affects login, not subsequent authed commands.)
 */
export function resolveLoginServer(
  env: NodeJS.ProcessEnv,
  cached: string | null,
): string {
  return env["TRIPWIRE_SERVER"] || cached || DEFAULT_SERVER;
}
