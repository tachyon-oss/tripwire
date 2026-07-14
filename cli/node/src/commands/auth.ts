/**
 * Auth commands: `auth login`, `auth logout`, `auth status`.
 *
 * The email-code flow itself lives in `util/login.ts`, because `Session` drives
 * it too (automatic sign-in). `logout` and `status` deliberately never trigger
 * that: they ask about auth state rather than consuming it.
 */
import { isExpired } from "../config/credentials.js";
import { CliError } from "../util/errors.js";
import { identityLine } from "../util/format.js";
import { out } from "../util/io.js";
import type { Session } from "../util/session.js";

export interface LoginOptions {
  email?: string;
}

export async function runLogin(session: Session, opts: LoginOptions): Promise<void> {
  const creds = await session.login(opts.email);
  out(`logged in as ${creds.user_id}`);
}

export function runLogout(session: Session): void {
  out(session.store.clear() ? "cached token removed" : "no cached token");
}

/** UTC minute precision: enough to answer "do I need to log in again today?" */
function expiryText(expiresAt: number): string {
  return `${new Date(expiresAt * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/**
 * `auth status`: the login state (identity, server, token expiry). Never signs
 * anyone in. Exits nonzero when logged out, so scripts can test it.
 */
export function runAuthStatus(session: Session): void {
  const creds = session.currentCredentials();
  if (!creds) {
    throw new CliError("not logged in. run `tripwire auth login`.");
  }
  out(identityLine(creds));
  out(
    isExpired(creds)
      ? "session: expired. run `tripwire auth login`"
      : `session: valid until ${expiryText(creds.expires_at)}`,
  );
}
