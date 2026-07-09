/**
 * Thin stdout/stderr helpers. Kept centralized so the placement delivery
 * contract — rendered block on STDOUT, all reporting on STDERR — is enforced in
 * one place and easy to reason about.
 */

/** Write a line to stdout (the machine/redirect channel). */
export function out(line = ""): void {
  process.stdout.write(`${line}\n`);
}

/** Write raw bytes to stdout with no added newline (text or binary). */
export function outRaw(data: string | Uint8Array): void {
  process.stdout.write(data);
}

/** Write a line to stderr (the human/reporting channel). */
export function err(line = ""): void {
  process.stderr.write(`${line}\n`);
}

/** Pretty-print a value as indented JSON to stdout. */
export function printJson(value: unknown): void {
  out(JSON.stringify(value, null, 2));
}
