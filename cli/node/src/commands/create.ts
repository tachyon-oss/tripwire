/**
 * `tripwire canary create <type>` — the create command, covering both ordinary
 * canary types and AWS placements. Maps to the UNCHANGED `POST /canary`; the
 * placement paths render the returned one-time credential into a config block.
 */
import { chmodSync, writeFileSync } from "node:fs";

import { ApiError } from "../api/errors.js";
import { deliverToFile, deliverToStdout } from "../placements/deliver.js";
import { generateName } from "../placements/namegen.js";
import { assertSafeName } from "../placements/opsec.js";
import { type PlacementDef, resolvePlacement } from "../placements/index.js";
import { dottedForWire, resolveType, type TypeEntry } from "../types/registry.js";
import { CliError } from "../util/errors.js";
import { armedWord } from "../util/format.js";
import { err, out } from "../util/io.js";
import type { Session } from "../util/session.js";

export interface CreateOptions {
  /** Positional type or placement id (the only way to name the type). */
  type?: string;
  name?: string;
  note?: string;
  expires?: string;
  output?: string;
}

const CREATING_HINT = "creating your canary…";

export async function runCreate(session: Session, opts: CreateOptions): Promise<void> {
  const typeInput = opts.type;
  if (!typeInput) {
    throw new CliError(
      "a canary type is required. run `tripwire canary create --help` for the list.",
    );
  }

  const placement = resolvePlacement(typeInput);
  if (placement) {
    await runPlacementCreate(session, placement, opts);
    return;
  }
  await runTypeCreate(session, resolveType(typeInput), opts);
}

/** Ordinary create: mint the canary and print its one-time credential fields. */
async function runTypeCreate(
  session: Session,
  entry: TypeEntry,
  opts: CreateOptions,
): Promise<void> {
  if (opts.name) {
    err(`note: --name applies only to placements; ignoring it for ${entry.id}.`);
  }
  const payload: Record<string, unknown> = { type: entry.wire };
  if (opts.note) payload["memo"] = opts.note;
  if (opts.expires) payload["expires_at"] = opts.expires;

  err(CREATING_HINT);
  const result = await createOrExplain(session, payload, entry.waitSeconds);

  if (opts.output) {
    writeJsonReveal(result, opts.output);
    return;
  }
  printReveal(entry, result);
}

/** Placement create: mint `aws.access_key` and render it into a config block. */
async function runPlacementCreate(
  session: Session,
  placement: PlacementDef,
  opts: CreateOptions,
): Promise<void> {
  const entry = resolveType(placement.underlyingType);

  // Resolve the block label: an explicit --name (OPSEC-gated) or an organic
  // `{context}-{role}` default.
  let name: string;
  if (opts.name) {
    assertSafeName(opts.name);
    name = opts.name;
  } else {
    name = generateName({ roles: placement.roles });
  }

  // Provenance auto-fills into the memo when the user omits --note; the note is
  // NEVER rendered into the file.
  const userNote = opts.note;
  const memo =
    userNote ??
    `${placement.id} ${name}${opts.output ? ` (${opts.output})` : ""}`;

  const payload: Record<string, unknown> = { type: entry.wire, memo };
  if (opts.expires) payload["expires_at"] = opts.expires;

  err(CREATING_HINT);
  const result = await createOrExplain(session, payload, entry.waitSeconds);

  const accessKeyId = str(result["access_key_id"]);
  const secretAccessKey = str(result["secret_access_key"]);
  const region = str(result["region"]);
  if (!accessKeyId || !secretAccessKey) {
    // The canary was minted but we cannot render the block. Never drop the
    // one-time secret: dump the raw create JSON to stdout (safety valve), then
    // error so the exit code reflects the failure.
    err("");
    err("!! the create response did not include the expected AWS credential fields.");
    err("!! the canary was minted; its raw one-time response is shown below — capture it now.");
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    throw new CliError(
      "could not render the placement block; the raw create response was printed above.",
    );
  }

  const block = placement.render(name, {
    accessKeyId,
    secretAccessKey,
    region,
  });
  const label = block.split("\n", 1)[0] ?? `[${name}]`;

  // All reporting goes to stderr so stdout carries only the block.
  const noteSuffix = userNote ? ` ; note: ${userNote}` : "";
  err(
    `${str(result["id"])}  ${dottedForWire(str(result["type"]))}  ` +
      `${armedWord(str(result["status"]))}  (via ${placement.id}) ; name: ${name}${noteSuffix}`,
  );
  err("one-time credential — it will NOT be shown again.");

  if (opts.output) {
    deliverToFile(block, opts.output, label);
  } else {
    deliverToStdout(block);
    err(`next: append the block above to ${placement.targetFile}`);
  }
}

/**
 * Run `POST /canary`, translating the create-specific failures (a still-
 * provisioning orphan; a hard provisioning failure) into actionable messages.
 * Mirrors the Python client's create error handling.
 */
async function createOrExplain(
  session: Session,
  payload: Record<string, unknown>,
  waitSeconds: number,
): Promise<Record<string, unknown>> {
  try {
    return await session.authedClient().createCanary(payload, waitSeconds * 1000);
  } catch (error) {
    if (error instanceof ApiError) {
      const message = createErrorMessage(error);
      if (message !== null) throw new CliError(message);
    }
    throw error;
  }
}

/** Friendly text for create-specific failures, or `null` to fall through. */
export function createErrorMessage(error: ApiError): string | null {
  if (error.status === 429 && error.detail === "canary_pending") {
    return (
      "canary is still provisioning, so its one-time credential reveal was not " +
      "returned in this response and cannot be recovered. creating again would " +
      "mint a second canary and trip the per-type quota; instead, find this " +
      "orphan with `tripwire canary list`, delete it with `tripwire canary " +
      "delete <id>`, then recreate."
    );
  }
  if (error.status === 502 && error.detail === "provisioning_failed") {
    return (
      "canary provisioning failed; nothing was issued. try again, and if it " +
      "persists contact support."
    );
  }
  return null;
}

/** Human one-time reveal for an ordinary create (all fields to stdout). */
function printReveal(entry: TypeEntry, result: Record<string, unknown>): void {
  err("one-time credential — copy it now; it will NOT be shown again.");
  const dotted = dottedForWire(str(result["type"]) || entry.wire);
  const memo = result["memo"] ? `  ${str(result["memo"])}` : "";
  out(`${str(result["id"])}  ${dotted}  ${armedWord(str(result["status"]))}${memo}`);
  for (const field of entry.outputFields) {
    const value = result[field];
    if (value !== undefined && value !== null && value !== "") {
      out(`  ${field}: ${String(value)}`);
    }
  }
}

/**
 * Write the full create JSON to `outputPath` (mode 0600).
 *
 * The WRITE and the CHMOD are handled separately:
 * - if the write fails, dump the JSON to stdout with a loud warning (post-mint
 *   safety valve) so the one-time secret is never lost;
 * - if only the chmod fails (file already on disk, perms not tightened), warn
 *   about permissions — do NOT claim the write failed and do NOT re-dump the
 *   secret to stdout.
 */
function writeJsonReveal(result: Record<string, unknown>, outputPath: string): void {
  const text = `${JSON.stringify(result, null, 2)}\n`;
  try {
    writeFileSync(outputPath, text, { mode: 0o600 });
  } catch (writeError) {
    const reason = writeError instanceof Error ? writeError.message : String(writeError);
    err("");
    err(`!! could not write to ${outputPath}: ${reason}`);
    err("!! the credential was already minted and is shown below — capture it now.");
    process.stdout.write(text);
    return;
  }
  // The file exists now; tighten perms best-effort (writeFileSync's mode does not
  // re-apply to a pre-existing file). A chmod failure is a permissions warning
  // only — the secret is safely on disk, so do not re-dump it.
  try {
    chmodSync(outputPath, 0o600);
    err(`wrote the create response to ${outputPath} (mode 0600).`);
  } catch (chmodError) {
    const reason = chmodError instanceof Error ? chmodError.message : String(chmodError);
    err(
      `wrote the create response to ${outputPath}, but could not set mode 0600 ` +
        `(${reason}); tighten it yourself: chmod 600 ${outputPath}`,
    );
  }
}

function str(value: unknown): string {
  return value === undefined || value === null ? "" : String(value);
}
