/**
 * Shared human-format helpers: the identity line (whoami == first line of
 * status) and canary-row rendering used by status / list / show.
 */
import type { Credentials } from "../config/credentials.js";
import { dottedForWire } from "../types/registry.js";

/** A canary summary as the server returns it (wire shape; snake type). */
export interface CanarySummary {
  id: string;
  type: string;
  status?: string | null;
  desired_status?: string | null;
  pending_change?: boolean;
  memo?: string | null;
  last_used_at?: string | null;
  [key: string]: unknown;
}

/**
 * The identity line: `user_id  email  server`. `email` is shown when present;
 * `server` only for a non-default (self-hosted / test) target, matching the
 * Python `whoami`. This single line is both `whoami` and the first line of
 * `status`.
 */
export function identityLine(creds: Credentials): string {
  const parts = [creds.user_id];
  if (creds.email) parts.push(creds.email);
  if (creds.server) parts.push(creds.server);
  return parts.join("  ");
}

/** A canary has fired when it carries a `last_used_at` timestamp. */
export function hasFired(canary: CanarySummary): boolean {
  return Boolean(canary.last_used_at);
}

/** The armed/disarmed word for a status value (`active` => `armed`). */
export function armedWord(status: string | null | undefined): string {
  if (status === "active") return "armed";
  if (status === "inactive") return "disarmed";
  return status || "unknown";
}

/** A one-line canary row for the `status`/`list` tables. */
export function canaryRow(canary: CanarySummary): string {
  const dotted = dottedForWire(canary.type);
  const state = hasFired(canary)
    ? `used ${canary.last_used_at}`
    : armedWord(canary.status);
  const memo = canary.memo ? `  ${canary.memo}` : "";
  return `  ${canary.id}  ${dotted}  ${state}${memo}`;
}
