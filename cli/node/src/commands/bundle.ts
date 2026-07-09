/**
 * Bundle commands: `download` (primary), `show`, `contents`, `create`.
 *
 * The bundle endpoints are PUBLIC on the server (no auth), but the CLI still
 * requires login for uniformity: every command resolves `session.authedClient()`
 * first, which throws `NoCredentialsError` (the standard "run `tripwire login`"
 * message + nonzero exit) BEFORE any request is made. The cached token is
 * attached to the requests too — the endpoints ignore it, so behavior matches
 * the rest of the CLI.
 */
import {
  existsSync,
  mkdirSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { unzipSync } from "fflate";

import type { ApiClient } from "../api/client.js";
import { ApiError } from "../api/errors.js";
import { CliError } from "../util/errors.js";
import { err, out, outRaw, printJson } from "../util/io.js";
import type { Session } from "../util/session.js";

/** Backoff schedule (ms) between download retries while a bundle is preparing. */
const RETRY_BACKOFF_MS = [750, 1500, 2500];

function realSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Friendly text for the shared bundle error responses, or `null` to fall through. */
function bundleErrorMessage(error: unknown): string | null {
  if (!(error instanceof ApiError)) return null;
  if (error.status === 404) {
    return "bundle not found; check the id.";
  }
  if (error.status === 410) {
    return `bundle is ${error.detail} and can no longer be accessed.`;
  }
  if (error.status === 409 && error.detail === "bundle_preparing") {
    return "the bundle is still being prepared; try again shortly.";
  }
  if (error.status === 429) {
    return "rate limited; wait a few minutes and try again.";
  }
  if (error.status === 400 && error.detail === "challenge_failed") {
    return "bundle creation requires browser verification; download it from https://tripwire.so.";
  }
  return null;
}

/** Run `fn`, remapping known bundle API errors to clean CLI messages. */
async function withBundleErrors<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    const message = bundleErrorMessage(error);
    if (message !== null) throw new CliError(message);
    throw error;
  }
}

/**
 * Download a bundle, retrying while the server reports `409 bundle_preparing`.
 * Any other error propagates immediately. On exhausted retries the last `409`
 * propagates (mapped to a clear message).
 */
export async function downloadWithRetry(
  client: Pick<ApiClient, "downloadBundle">,
  id: string,
  opts: { attempts?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<{ headers: Headers; buffer: Buffer }> {
  const attempts = opts.attempts ?? RETRY_BACKOFF_MS.length + 1;
  const sleep = opts.sleep ?? realSleep;
  let lastError: ApiError | undefined;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return await client.downloadBundle(id);
    } catch (error) {
      const preparing =
        error instanceof ApiError &&
        error.status === 409 &&
        error.detail === "bundle_preparing";
      if (!preparing) throw error;
      lastError = error as ApiError;
      if (attempt < attempts - 1) {
        await sleep(RETRY_BACKOFF_MS[attempt] ?? RETRY_BACKOFF_MS[RETRY_BACKOFF_MS.length - 1]!);
      }
    }
  }
  throw lastError ?? new ApiError(409, "bundle_preparing");
}

/**
 * Parse the download filename from a `Content-Disposition` header, preferring
 * the RFC 5987 `filename*` form. Returns the basename only (no path parts), or
 * `null` if none is present.
 */
export function filenameFromDisposition(value: string | null | undefined): string | null {
  if (!value) return null;
  const extended = /filename\*=(?:UTF-8'')?["']?([^"';]+)/i.exec(value);
  if (extended?.[1]) {
    try {
      return sanitizeFilename(decodeURIComponent(extended[1].trim()));
    } catch {
      // Malformed percent-encoding (URIError): fall through to the plain form,
      // and ultimately to the caller's `${bundleId}.zip` default.
    }
  }
  const plain = /filename="?([^"';]+)"?/i.exec(value);
  if (plain?.[1]) return sanitizeFilename(plain[1].trim());
  return null;
}

function sanitizeFilename(name: string): string {
  return basename(name.replace(/\\/g, "/"));
}

function isExistingDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Extract a zip `buffer` into `dir`, guarding against zip-slip: any entry that
 * is absolute or resolves outside `dir` (`..`) is SKIPPED, not written, even
 * though the archive comes from our own server. Intermediate dirs are created;
 * files are written with normal perms. Returns the count written and the names
 * skipped.
 */
export function extractZip(
  buffer: Uint8Array,
  dir: string,
): { written: number; skipped: string[] } {
  const entries = unzipSync(buffer);
  const root = resolve(dir);
  const skipped: string[] = [];
  let written = 0;
  for (const [rawName, data] of Object.entries(entries)) {
    const name = rawName.replace(/\\/g, "/");
    if (name.endsWith("/")) continue; // directory entry — created implicitly below
    if (isUnsafeEntry(name, root)) {
      skipped.push(rawName);
      continue;
    }
    const target = resolve(root, name);
    // The extracted files hold planted credentials: dirs 0700, files 0600.
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, data, { mode: 0o600 });
    written++;
  }
  return { written, skipped };
}

/** True when a zip entry is absolute or escapes `root` via `..`. */
function isUnsafeEntry(name: string, root: string): boolean {
  if (name.startsWith("/") || isAbsolute(name)) return true;
  const rel = relative(root, resolve(root, name));
  return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

/** A path for display: bare names get a `./` prefix to read as a local path. */
function displayPath(path: string): string {
  return path.startsWith("/") || path.startsWith(".") || path.startsWith("~")
    ? path
    : `./${path}`;
}

/** Human byte size, decimal (kB/MB), matching the `48.2 kB` style. */
function humanBytes(bytes: number): string {
  if (bytes < 1000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1000).toFixed(1)} kB`;
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

export interface BundleDownloadOptions {
  output?: string;
  zip?: boolean;
}

export async function runBundleDownload(
  session: Session,
  id: string | undefined,
  opts: BundleDownloadOptions,
): Promise<void> {
  const client = session.authedClient(); // login guard: throws before any request.
  await withBundleErrors(async () => {
    // No id given: issue a fresh bundle for the logged-in user first, then
    // download it. The create body is empty — the auth-derived recipient and the
    // template are both chosen server-side (no email / turnstile_token / template).
    let bundleId = id;
    if (!bundleId) {
      const created = (await client.createBundle({})) as { bundle_id?: string };
      if (!created.bundle_id) {
        throw new CliError("bundle creation did not return an id; nothing to download.");
      }
      bundleId = created.bundle_id;
      err(`created bundle ${bundleId} for you; downloading…`);
    }

    const { headers, buffer } = await downloadWithRetry(client, bundleId);
    const filename =
      filenameFromDisposition(headers.get("content-disposition")) ?? `${bundleId}.zip`;
    // `<name>` = the filename without its `.zip` suffix (fallback: bundle id).
    const name = filename.replace(/\.zip$/i, "") || bundleId;

    // `-o -` streams the raw zip bytes to stdout (for piping), taking precedence.
    if (opts.output === "-") {
      outRaw(buffer);
      err(`wrote ${buffer.length} bytes to stdout`);
      return;
    }

    // `--zip` keeps the raw archive instead of extracting.
    if (opts.zip) {
      const dest = opts.output
        ? isExistingDirectory(opts.output)
          ? join(opts.output, filename)
          : opts.output
        : filename;
      // Refuse to clobber an existing archive (matches the extract path's
      // non-empty-dir guard).
      if (existsSync(dest)) {
        throw new CliError(
          `${displayPath(dest)} already exists; remove it or pass a different -o path.`,
        );
      }
      writeFileSync(dest, buffer, { mode: 0o600 });
      err(`saved ${filename} (${humanBytes(buffer.length)}) → ${displayPath(dest)}`);
      return;
    }

    // DEFAULT: extract into `./<name>/` (or `-o <dir>`).
    const dir = opts.output ?? name;
    if (existsSync(dir)) {
      if (!statSync(dir).isDirectory()) {
        throw new CliError(
          `${displayPath(dir)} exists and is not a directory; pass -o <dir> or use --zip.`,
        );
      }
      if (readdirSync(dir).length > 0) {
        throw new CliError(
          `target directory ${displayPath(dir)} already exists and is not empty; ` +
            `remove it or pass -o <empty-dir> (or use --zip to keep the archive).`,
        );
      }
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 }); // holds planted credentials
    const { written, skipped } = extractZip(buffer, dir);
    for (const bad of skipped) err(`skipped unsafe zip entry: ${bad}`);
    err(`extracted ${written} files → ${displayPath(dir)}/`);
  });
}

export interface BundleShowOptions {
  json?: boolean;
}

interface BundleInfo {
  status?: string;
  expires_at?: string;
  placements?: Record<string, string[]>;
}

export async function runBundleShow(
  session: Session,
  id: string,
  opts: BundleShowOptions,
): Promise<void> {
  const client = session.authedClient();
  const info = (await withBundleErrors(() => client.getBundle(id))) as BundleInfo;
  if (opts.json) {
    printJson(info);
    return;
  }
  out(`status:   ${info.status ?? "unknown"}`);
  out(`expires:  ${info.expires_at ?? "unknown"}`);
  const placements = info.placements ?? {};
  const files = Object.keys(placements);
  if (files.length === 0) {
    out("placements: (none yet — populated on first download)");
    return;
  }
  out("placements:");
  for (const file of files) {
    out(`  ${file}`);
    for (const entry of placements[file] ?? []) out(`    ${entry}`);
  }
}

export interface BundleContentsOptions {
  json?: boolean;
}

interface BundleContents {
  template_id?: string;
  template_version?: string;
  files?: Array<{ path: string; size: number; content?: string }>;
}

export async function runBundleContents(
  session: Session,
  id: string,
  opts: BundleContentsOptions,
): Promise<void> {
  const client = session.authedClient();
  const contents = (await withBundleErrors(() => client.bundleContents(id))) as BundleContents;
  if (opts.json) {
    printJson(contents);
    return;
  }
  out(`template: ${contents.template_id ?? "unknown"} @ ${contents.template_version ?? "?"}`);
  const files = contents.files ?? [];
  out(`files (${files.length}):`);
  for (const file of files) out(`  ${file.path}  (${file.size} bytes)`);
}

interface BundleCreateResult {
  bundle_id?: string;
  expires_at?: string;
  status?: string;
}

export async function runBundleCreate(session: Session): Promise<void> {
  const client = session.authedClient();
  // The CLI is always authenticated, so the backend issues the bundle for the
  // logged-in user. The request body is empty: no email, turnstile_token, or
  // template_id (template selection is internal — the server picks).
  const result = (await withBundleErrors(() => client.createBundle({}))) as BundleCreateResult;
  out(`bundle_id:  ${result.bundle_id ?? "unknown"}`);
  out(`expires:    ${result.expires_at ?? "unknown"}`);
  if (result.bundle_id) {
    err(`download it with: tripwire bundle download ${result.bundle_id}`);
  }
}
