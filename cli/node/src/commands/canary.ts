/**
 * Canary read + lifecycle commands: `list`, `show`, `delete`.
 * `create` lives in `create.ts`.
 */
import { resolveType } from "../types/registry.js";
import { canaryRow, type CanarySummary, hasFired } from "../util/format.js";
import { out, printJson } from "../util/io.js";
import type { Session } from "../util/session.js";

interface ListResponse {
  canaries?: CanarySummary[];
}

export interface ListOptions {
  type?: string;
  fired?: boolean;
  json?: boolean;
}

export async function runList(session: Session, opts: ListOptions): Promise<void> {
  const response = (await (await session.authedClient()).listCanaries()) as ListResponse;
  let canaries = response.canaries ?? [];

  if (opts.type) {
    const wire = resolveType(opts.type).wire;
    canaries = canaries.filter((c) => c.type === wire);
  }
  if (opts.fired) {
    canaries = canaries.filter(hasFired);
  }

  if (opts.json) {
    // Verbatim server truth (filtered), snake types preserved for scripts.
    printJson({ canaries });
    return;
  }
  if (canaries.length === 0) {
    out("no canaries match.");
    return;
  }
  for (const canary of canaries) out(canaryRow(canary).trimStart());
}

export interface ShowOptions {
  json?: boolean;
}

export async function runShow(
  session: Session,
  id: string,
  opts: ShowOptions,
): Promise<void> {
  const canary = (await (await session.authedClient()).getCanary(id)) as CanarySummary;
  if (opts.json) {
    printJson(canary);
    return;
  }
  out(canaryRow(canary).trimStart());
  if (hasFired(canary)) {
    out(`fired: last used ${canary.last_used_at}`);
  } else {
    out("fired: no hits yet");
  }
  out(`actions: tripwire canary delete ${id}`);
}

export async function runDelete(session: Session, id: string): Promise<void> {
  printJson(await (await session.authedClient()).deleteCanary(id));
}
