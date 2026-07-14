/**
 * `tripwire status` — the cross-object "did anything fire?" dashboard. Prints
 * the identity line, counts, then FIRED canaries first, then the rest.
 * `--watch` re-polls; `--json` emits verbatim server truth.
 */
import { CliError } from "../util/errors.js";
import { canaryRow, type CanarySummary, hasFired, identityLine } from "../util/format.js";
import { err, out, printJson } from "../util/io.js";
import type { Session } from "../util/session.js";

export interface StatusOptions {
  watch?: boolean;
  json?: boolean;
}

interface ListResponse {
  canaries?: CanarySummary[];
}

export async function runStatus(session: Session, opts: StatusOptions): Promise<void> {
  if (opts.watch && opts.json) {
    // Watch is a live human view; JSON is a one-shot machine read.
    err("note: --watch is ignored with --json.");
    opts = { ...opts, watch: false };
  }
  if (!opts.watch) {
    await renderOnce(session, opts.json ?? false);
    return;
  }
  // Resolve auth once up front (signing in if needed), then poll every 5s,
  // clearing the screen between frames, until interrupted. A transient error
  // between frames is tolerated: warn and keep polling rather than exiting.
  await session.requireCredentials();
  for (;;) {
    process.stdout.write("\x1b[2J\x1b[H");
    try {
      await renderOnce(session, false);
    } catch (error) {
      // A cancelled sign-in, or a refusal to sign in at all, is the user's
      // decision -- not a blip to ride out. Retrying it would re-prompt every
      // five seconds and swallow the Ctrl+C they just pressed to escape.
      if (error instanceof CliError) throw error;
      const message = error instanceof Error ? error.message : String(error);
      err(`(temporary error: ${message}; retrying in 5s…)`);
    }
    await sleep(5000);
  }
}

async function renderOnce(session: Session, json: boolean): Promise<void> {
  const creds = await session.requireCredentials();
  const response = (await (await session.authedClient()).listCanaries()) as ListResponse;
  if (json) {
    printJson(response);
    return;
  }
  const canaries = response.canaries ?? [];
  const fired = canaries.filter(hasFired);
  const rest = canaries.filter((c) => !hasFired(c));

  out(identityLine(creds));
  out();
  out(`${canaries.length} canaries, ${fired.length} fired`);

  if (canaries.length === 0) {
    out();
    out("no canaries yet. create one with `tripwire canary create <type>`.");
    return;
  }
  if (fired.length > 0) {
    out();
    out("FIRED");
    for (const canary of fired) out(canaryRow(canary));
  }
  if (rest.length > 0) {
    out();
    out("ARMED");
    for (const canary of rest) out(canaryRow(canary));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
