/**
 * `tripwire api <METHOD> <path> [body]` — the gh-style escape hatch: a generic
 * authenticated passthrough to the REST API for anything the porcelain lacks.
 * `--json` prints the raw response body; otherwise it is pretty-printed when it
 * is JSON. Also mounted as `tripwire canary api ...`.
 */
import { CREATE_READ_TIMEOUT_MS } from "../api/client.js";
import { CliError } from "../util/errors.js";
import { err, out, outRaw } from "../util/io.js";
import type { Session } from "../util/session.js";

export interface ApiOptions {
  json?: boolean;
  /** Read timeout override, in seconds (string from commander). */
  timeout?: string;
}

export async function runApi(
  session: Session,
  method: string,
  path: string,
  body: string | undefined,
  opts: ApiOptions,
): Promise<void> {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  let parsedBody: unknown;
  if (body !== undefined && body !== "") {
    try {
      parsedBody = JSON.parse(body);
    } catch {
      throw new CliError(`request body is not valid JSON: ${body}`);
    }
  }

  // Default to the create-read floor (~240s), not the 10s default: `tripwire api
  // POST /canary` triggers a synchronous provider mint that can take ~180s, and a
  // short timeout would abort it and lose the one-time reveal. `--timeout`
  // overrides.
  let timeoutMs = CREATE_READ_TIMEOUT_MS;
  if (opts.timeout !== undefined) {
    const seconds = Number(opts.timeout);
    if (!Number.isFinite(seconds) || seconds <= 0) {
      throw new CliError(`invalid --timeout "${opts.timeout}": must be a positive number of seconds`);
    }
    timeoutMs = seconds * 1000;
  }

  const raw = await session.authedClient().requestRaw(method.toUpperCase(), normalizedPath, {
    body: parsedBody,
    timeoutMs,
  });

  if (!raw.ok) {
    err(`HTTP ${raw.status}`);
    process.exitCode = 1;
  }

  if (opts.json || !raw.text) {
    // Verbatim server bytes.
    outRaw(raw.text);
    if (raw.text && !raw.text.endsWith("\n")) outRaw("\n");
    return;
  }
  try {
    out(JSON.stringify(JSON.parse(raw.text), null, 2));
  } catch {
    outRaw(raw.text.endsWith("\n") ? raw.text : `${raw.text}\n`);
  }
}
