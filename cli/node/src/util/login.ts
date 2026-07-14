/**
 * The interactive email-code login flow, with no dependency on `Session`.
 *
 * Two callers drive it: `tripwire auth login`, and the automatic sign-in
 * `Session.requireCredentials()` performs when a command needs auth and there is
 * no usable cached token. Keeping it here (rather than in `commands/auth.ts`,
 * which imports `Session`) is what keeps the import graph acyclic.
 */
import type { ApiClient } from "../api/client.js";
import { ApiError } from "../api/errors.js";
import { type Credentials, DEFAULT_SERVER } from "../config/credentials.js";
import { CliError } from "./errors.js";
import type { Prompter } from "./prompt.js";

const EMAIL_CODE_ATTEMPTS = 3;

export interface EmailLoginOptions {
  /** From `--email`; skips the email prompt entirely. */
  emailFlag?: string;
  /** Prompt default: the address from the last login. */
  defaultEmail?: string | null;
}

/**
 * Call `/auth/login/start` once (it is rate-limited), then prompt for the
 * 6-digit code, re-prompting in-band on an invalid or expired code without
 * re-calling start.
 */
export async function emailLogin(
  client: ApiClient,
  server: string,
  prompter: Prompter,
  opts: EmailLoginOptions = {},
): Promise<Credentials> {
  const email = opts.emailFlag || (await prompter.ask("email", opts.defaultEmail));
  if (!email) throw new CliError("an email address is required to log in.");

  await startEmailLogin(client, email);
  prompter.notify(`sent a 6-digit sign-in code to ${email}; check your inbox.`);

  let lastError: ApiError | null = null;
  for (let attempt = 0; attempt < EMAIL_CODE_ATTEMPTS; attempt++) {
    const code = await prompter.ask("code");
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
          prompter.notify(`invalid or expired code; ${remaining} attempt(s) left.`);
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
          "`tripwire auth login` again.",
      );
    }
    throw error;
  }
}

/**
 * Exchange a code for a token. A 5xx here is the dangerous case: the code may
 * already have been consumed, so retrying it is futile and silently re-sending
 * one would burn the rate-limited start. Surface a clear message and have the
 * user re-run `tripwire auth login` for a fresh code.
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
          "auth login` again to request a fresh code.",
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
        "run `tripwire auth login` again.",
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
