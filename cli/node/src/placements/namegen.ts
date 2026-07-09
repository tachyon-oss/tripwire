/**
 * Organic default `--name` generation for placements: `{context}-{role}`.
 *
 * context = the git repo basename (or cwd basename) IF it normalizes to a safe
 * slug and passes the OPSEC ban scan; otherwise it is dropped and the name is
 * just `{role}`. role is drawn from a mundane per-placement wordlist. The goal
 * is a label that looks like an ordinary developer credential, never a tell.
 */
import { execFileSync } from "node:child_process";
import { basename } from "node:path";

import { findBannedTerm } from "./opsec.js";

/** Mundane role words for the generated `{context}-{role}` default. */
export const DEFAULT_ROLES: readonly string[] = [
  "deploy",
  "s3-sync",
  "backups",
  "readonly",
  "terraform",
  "billing",
  "data-export",
  "ci",
];

export interface NameGenDeps {
  /** Role wordlist to draw from. */
  roles?: readonly string[];
  /** Pick a role from the wordlist (injectable for deterministic tests). */
  pickRole?: (roles: readonly string[]) => string;
  /** Resolve the raw context string (repo/cwd name) — injectable for tests. */
  resolveContext?: () => string | null;
}

/** Normalize a raw context into a safe slug, or `null` if unusable. */
export function normalizeContext(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const slug = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!slug) return null;
  // A context that itself trips the OPSEC scan is dropped, not sanitized.
  if (findBannedTerm(slug) !== null) return null;
  return slug;
}

/** Best-effort context: the git repo toplevel basename, else the cwd basename. */
export function defaultContext(cwd: string = process.cwd()): string | null {
  try {
    const top = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf8",
      timeout: 5000,
    }).trim();
    if (top) return basename(top);
  } catch {
    // not a git repo (or git missing) — fall back to the cwd basename.
  }
  return basename(cwd) || null;
}

function defaultPickRole(roles: readonly string[]): string {
  const idx = Math.floor(Math.random() * roles.length);
  return roles[idx] ?? roles[0] ?? "deploy";
}

/** Generate an organic `{context}-{role}` (or `{role}`) placement name. */
export function generateName(deps: NameGenDeps = {}): string {
  const roles = deps.roles ?? DEFAULT_ROLES;
  const pickRole = deps.pickRole ?? defaultPickRole;
  const resolveContext = deps.resolveContext ?? (() => defaultContext());
  const role = pickRole(roles);
  const context = normalizeContext(resolveContext());
  return context ? `${context}-${role}` : role;
}
