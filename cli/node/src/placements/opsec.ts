/**
 * OPSEC banned-term gate for user-supplied placement `--name` values.
 *
 * A placement writes a `[profile <name>]` / `[<name>]` block into a REAL config
 * file the attacker will read. A name that contains decoy vocabulary
 * ("canary", "honeypot", ...) blows the cover, so the gate rejects it.
 *
 * This is a RUNTIME feature applied to user input — not a constraint on this
 * package's own source, where "canary"/"tripwire" are the product's own words.
 */
import { CliError } from "../util/errors.js";

/**
 * Distinctive decoy vocabulary that is a tell ANYWHERE it appears, so it is
 * matched as a plain (case-insensitive) substring.
 */
export const HARD_BANNED_TERMS: readonly string[] = [
  "canary",
  "tripwire",
  "planted",
  "honeypot",
];

/**
 * Short, generic placement extras. These are common English
 * fragments ("trap" ⊂ "bootstrap", "bait" ⊂ "sbaiting"), so they are matched as
 * WHOLE WORDS (bounded by non-alphanumerics) to avoid rejecting mundane names.
 */
export const WORD_BANNED_TERMS: readonly string[] = [
  "honeytoken",
  "decoy",
  "bait",
  "trap",
];

/** The full vendored ban list (for conformance/superset checks). */
export const BANNED_TERMS: readonly string[] = [...HARD_BANNED_TERMS, ...WORD_BANNED_TERMS];

/**
 * The banned term contained in `value` (case-insensitive), or `null`. Hard terms
 * match as substrings; the short generic extras match only as whole words, so
 * "bootstrap"/"decoymodel" are not false-positives while "prod-trap" is caught.
 */
export function findBannedTerm(value: string): string | null {
  const lowered = value.toLowerCase();
  for (const term of HARD_BANNED_TERMS) {
    if (lowered.includes(term)) return term;
  }
  for (const term of WORD_BANNED_TERMS) {
    // Whole-word: the term is not flanked by another alphanumeric character.
    if (new RegExp(`(?<![a-z0-9])${term}(?![a-z0-9])`).test(lowered)) return term;
  }
  return null;
}

export class OpsecError extends CliError {
  constructor(message: string) {
    super(message);
    this.name = "OpsecError";
  }
}

/**
 * Reject a `--name` that contains operator vocabulary, with a didactic error
 * explaining WHY (the name lands in a file an attacker reads, so it must look
 * like an ordinary credential label).
 */
export function assertSafeName(name: string): void {
  const term = findBannedTerm(name);
  if (term !== null) {
    throw new OpsecError(
      `--name "${name}" contains the banned term "${term}".\n` +
        `this label is written into a real config file that an intruder reads, ` +
        `so it must look like an ordinary credential — not a canary. choose a ` +
        `mundane, organic name (e.g. "prod-deploy", "s3-backups").`,
    );
  }
}
