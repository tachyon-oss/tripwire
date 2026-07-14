/**
 * Shared CLI error handling: a `CliError` for clean user-facing failures, a 401
 * message mapper, and an `action()` wrapper that turns known errors into a tidy
 * stderr message + nonzero exit instead of a Node stack trace.
 */
import { ApiError } from "../api/errors.js";
import { NoCredentialsError } from "../config/credentials.js";
import { err } from "./io.js";

/** A clean, user-facing CLI failure (no stack trace shown). */
export class CliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliError";
  }
}

/**
 * Substrings the server leaks on a 401 when the cached token is malformed or
 * undecodable. Opaque to users, so map them to a plain "session expired" message
 * instead of echoing the raw detail.
 */
const EXPIRED_SESSION_MARKERS = [
  "invalid header padding",
  "invalid token",
  "not enough segments",
  "signature",
  "expired",
  "decrypt",
];

export function unauthorizedMessage(detail: string): string {
  const lowered = detail.toLowerCase();
  if (EXPIRED_SESSION_MARKERS.some((m) => lowered.includes(m))) {
    return "session expired; run `tripwire auth login`";
  }
  return `401: ${detail}\nhint: run \`tripwire auth login\``;
}

/** Translate a known error into user-facing text, or `null` to re-throw. */
function messageFor(error: unknown): string | null {
  if (error instanceof CliError) return error.message;
  if (error instanceof NoCredentialsError) return error.message;
  // readline rejects with an AbortError when the user hits Ctrl+C / Ctrl+D at a
  // prompt. Backing out of a prompt is never a crash; `TtyPrompter.ask` already
  // maps this, so this is the backstop for any other prompt we add later.
  if (error instanceof Error && error.name === "AbortError") return "sign-in cancelled.";
  if (error instanceof ApiError) {
    if (error.status === 401) return unauthorizedMessage(error.detail);
    return `${error.status}: ${error.detail}`;
  }
  return null;
}

/**
 * Wrap a command handler so known failures print `error: <msg>` to stderr and
 * exit 1, while unexpected errors still surface (with their stack) for debugging.
 */
export function action<A extends unknown[]>(
  handler: (...args: A) => void | Promise<void>,
): (...args: A) => Promise<void> {
  return async (...args: A) => {
    try {
      await handler(...args);
    } catch (error) {
      const message = messageFor(error);
      if (message === null) throw error;
      err(`error: ${message}`);
      process.exitCode = 1;
    }
  };
}
