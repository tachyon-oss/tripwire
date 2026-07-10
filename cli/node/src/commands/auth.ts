/**
 * Auth commands: `login`, `logout`.
 *
 * Login is interactive email-code auth mirroring the Python CLI: `/auth/login/
 * start` once (rate-limited), then re-prompt for the 6-digit code in-band on an
 * invalid/expired code without re-calling start.
 */
import { createInterface } from "node:readline/promises";

import type { ApiClient } from "../api/client.js";
import { ApiError } from "../api/errors.js";
import { type Credentials, DEFAULT_SERVER } from "../config/credentials.js";
import { CliError } from "../util/errors.js";
import { out } from "../util/io.js";
import type { Session } from "../util/session.js";

const EMAIL_CODE_ATTEMPTS = 3;

/** The email from a prior login (the local cache) as the prompt default, else
 *  null. Never derived from git or any other local identity. */
function cachedLoginEmail(session: Session): string | null {
  try {
    return session.load().email ?? null;
  } catch {
    return null;
  }
}

async function prompt(question: string, def?: string | null): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const suffix = def ? ` [${def}]` : "";
    const answer = (await rl.question(`${question}${suffix}: `)).trim();
    return answer || def || "";
  } finally {
    rl.close();
  }
}

export interface LoginOptions {
  email?: string;
}

export async function runLogin(session: Session, opts: LoginOptions): Promise<void> {
  const server = session.loginServer();
  const client = session.client(server);
  const creds = await emailLogin(client, server, opts.email, cachedLoginEmail(session));
  session.store.save(creds);
  out(`logged in as ${creds.user_id}`);
}

async function emailLogin(
  client: ApiClient,
  server: string,
  emailFlag: string | undefined,
  defaultEmail: string | null,
): Promise<Credentials> {
  const email = emailFlag || (await prompt("email", defaultEmail));
  if (!email) throw new CliError("an email address is required to log in.");

  await startEmailLogin(client, email);
  process.stderr.write(`sent a 6-digit sign-in code to ${email}; check your inbox.\n`);

  let lastError: ApiError | null = null;
  for (let attempt = 0; attempt < EMAIL_CODE_ATTEMPTS; attempt++) {
    const code = await prompt("code");
    try {
      const response = await exchangeCode(client, email, code);
      return credentialsFromLogin(server, response, email);
    } catch (error) {
      if (
        error instanceof ApiError &&
        error.status === 400 &&
        error.detail === "invalid_or_expired_code"
      ) {
        lastError = error;
        const remaining = EMAIL_CODE_ATTEMPTS - attempt - 1;
        if (remaining > 0) {
          process.stderr.write(
            `invalid or expired code; ${remaining} attempt(s) left.\n`,
          );
        }
        continue;
      }
      throw error;
    }
  }
  throw lastError ?? new ApiError(400, "invalid_or_expired_code");
}

/** Send the sign-in code; turn the rate-limit 429 into an actionable message. */
async function startEmailLogin(client: ApiClient, email: string): Promise<void> {
  try {
    await client.loginStart(email);
  } catch (error) {
    if (error instanceof ApiError && error.status === 429) {
      throw new CliError(
        "too many login attempts from this network; wait ~10 minutes and try " +
          "`tripwire login` again.",
      );
    }
    throw error;
  }
}

/**
 * Exchange a code for a token. A 5xx here is the dangerous case: the code may
 * already have been consumed, so retrying it is futile and silently re-sending
 * one would burn the rate-limited start. Surface a clear message and have the
 * user re-run `tripwire login` for a fresh code.
 */
async function exchangeCode(
  client: ApiClient,
  email: string,
  code: string,
): Promise<Record<string, unknown>> {
  try {
    return await client.loginWithCode(email, code);
  } catch (error) {
    if (error instanceof ApiError && error.status >= 500) {
      throw new CliError(
        `the server errored while verifying your code (${error.status}: ` +
          `${error.detail}); your code may already be spent. run \`tripwire ` +
          "login` again to request a fresh code.",
      );
    }
    throw error;
  }
}

function credentialsFromLogin(
  server: string,
  response: Record<string, unknown>,
  email: string,
): Credentials {
  const userId = response["user_id"];
  const accessToken = response["access_token"];
  const expiresAt = Number(response["expires_at"]);
  // Validate the required fields rather than coercing a missing value into the
  // literal string "undefined" (which would cache a broken, unusable token).
  if (
    typeof userId !== "string" ||
    userId === "" ||
    typeof accessToken !== "string" ||
    accessToken === "" ||
    !Number.isFinite(expiresAt)
  ) {
    throw new CliError(
      "the login response was malformed (missing user_id/access_token/expires_at); " +
        "run `tripwire login` again.",
    );
  }
  return {
    // Store the server only for a non-default (self-hosted / test) target.
    server: server === DEFAULT_SERVER ? null : server,
    user_id: userId,
    access_token: accessToken,
    expires_at: expiresAt,
    email,
  };
}

export function runLogout(session: Session): void {
  out(session.store.clear() ? "cached token removed" : "no cached token");
}
