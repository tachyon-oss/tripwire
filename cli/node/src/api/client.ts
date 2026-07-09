/**
 * HTTP client for the Tripwire REST API, built on the global `fetch` (Node
 * >=18). Deliberately mirrors the behavior of the Python `ApiClient`
 * (`public/tripwire_cli/tripwire_cli/client.py`) so the two clients are
 * interchangeable against the same server.
 */
import { ApiError } from "./errors.js";

/** Default read budget for ordinary requests, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * `POST /canary` is synchronous and provider-minted types can take ~12s/44s/100s
 * today; the server waits up to its `CANARY_CREATE_WAIT_SECONDS` (180s) before
 * it gives up. The client read timeout MUST stay above that window: if the
 * client abandons the request first, the server still creates the canary, the
 * one-time credential reveal is lost, and the per-type quota is consumed with no
 * recovery. This 240s floor lives in the type registry (`wait_seconds`); the
 * constant is the fallback default.
 */
export const CREATE_READ_TIMEOUT_MS = 240_000;

export interface RawResponse {
  status: number;
  ok: boolean;
  text: string;
}

export interface ApiClientOptions {
  baseUrl: string;
  token?: string | null;
  /** Injectable for tests; defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
}

export class ApiClient {
  readonly baseUrl: string;
  private readonly token: string | null;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: ApiClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token ?? null;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private headers(hasBody: boolean): Record<string, string> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.token) headers["authorization"] = `Bearer ${this.token}`;
    if (hasBody) headers["content-type"] = "application/json";
    return headers;
  }

  /**
   * Perform a request and return the raw status + body text. Network failures
   * and timeouts surface as `ApiError(0, ...)`; the caller decides how to
   * interpret non-2xx statuses.
   */
  async requestRaw(
    method: string,
    path: string,
    opts: { body?: unknown; timeoutMs?: number } = {},
  ): Promise<RawResponse> {
    const response = await this.send(method, path, opts);
    const text = await response.text();
    return { status: response.status, ok: response.ok, text };
  }

  /**
   * Perform a request and return the raw `Response` (body unread). Handles the
   * abort timeout and network-failure translation to `ApiError(0, ...)`; the
   * caller reads the body (text or binary).
   */
  private async send(
    method: string,
    path: string,
    opts: { body?: unknown; timeoutMs?: number } = {},
  ): Promise<Response> {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const hasBody = opts.body !== undefined;
    try {
      return await this.fetchImpl(this.baseUrl + path, {
        method,
        headers: this.headers(hasBody),
        body: hasBody ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new ApiError(
          0,
          `request to ${this.baseUrl}${path} timed out after ${Math.round(timeoutMs / 1000)}s`,
        );
      }
      // `fetch` wraps the real network error (ECONNREFUSED, ENOTFOUND, ...) as a
      // terse `TypeError: fetch failed` whose `.cause` holds the actual reason;
      // surface it so the message is diagnosable.
      const message = err instanceof Error ? err.message : String(err);
      const cause =
        err instanceof Error && err.cause !== undefined
          ? `: ${err.cause instanceof Error ? err.cause.message : String(err.cause)}`
          : "";
      throw new ApiError(0, `cannot reach ${this.baseUrl}: ${message}${cause}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Perform a request whose success body is BINARY (e.g. the bundle zip).
   * Raises `ApiError` on any non-2xx (decoding the JSON error detail), else
   * returns the response headers plus the body as a `Buffer`.
   */
  async download(
    method: string,
    path: string,
    opts: { body?: unknown; timeoutMs?: number } = {},
  ): Promise<{ headers: Headers; buffer: Buffer }> {
    const response = await this.send(method, path, opts);
    if (!response.ok) {
      const text = await response.text();
      throw new ApiError(response.status, errorDetail(text));
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    return { headers: response.headers, buffer };
  }

  /**
   * Perform a request, raising `ApiError` on any non-2xx status and returning
   * the parsed JSON body (or `{}` for an empty body).
   */
  async request<T = unknown>(
    method: string,
    path: string,
    opts: { body?: unknown; timeoutMs?: number } = {},
  ): Promise<T> {
    const raw = await this.requestRaw(method, path, opts);
    if (!raw.ok) {
      throw new ApiError(raw.status, errorDetail(raw.text));
    }
    if (!raw.text) return {} as T;
    return JSON.parse(raw.text) as T;
  }

  // ----- auth -----

  loginStart(email: string): Promise<unknown> {
    return this.request("POST", "/auth/login/start", { body: { email } });
  }

  loginWithCode(email: string, code: string): Promise<Record<string, unknown>> {
    return this.request("POST", "/auth/login", { body: { email, code } });
  }

  // ----- canary -----

  listCanaries(): Promise<unknown> {
    return this.request("GET", "/canary");
  }

  createCanary(
    payload: Record<string, unknown>,
    timeoutMs: number = CREATE_READ_TIMEOUT_MS,
  ): Promise<Record<string, unknown>> {
    return this.request("POST", "/canary", { body: payload, timeoutMs });
  }

  getCanary(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/canary/${encodeURIComponent(id)}`);
  }

  deactivateCanary(id: string): Promise<unknown> {
    return this.request("POST", `/canary/${encodeURIComponent(id)}/deactivate`);
  }

  deleteCanary(id: string): Promise<unknown> {
    return this.request("DELETE", `/canary/${encodeURIComponent(id)}`);
  }

  // ----- bundle (public server endpoints; the CLI still requires login) -----

  getBundle(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/bundles/${encodeURIComponent(id)}`);
  }

  bundleContents(id: string): Promise<Record<string, unknown>> {
    return this.request("POST", `/bundles/${encodeURIComponent(id)}/contents`);
  }

  createBundle(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/bundles", { body });
  }

  /** The download: `POST /bundles/{id}` returns a binary zip body. */
  downloadBundle(id: string): Promise<{ headers: Headers; buffer: Buffer }> {
    return this.download("POST", `/bundles/${encodeURIComponent(id)}`);
  }
}

/**
 * Best-effort human-readable detail from an error body: the JSON `detail` field
 * when present (stringifying object details like `quota_exceeded`), else the raw
 * body text.
 */
export function errorDetail(text: string): string {
  if (!text) return "";
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return text;
  }
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    return JSON.stringify(detail);
  }
  return text;
}
