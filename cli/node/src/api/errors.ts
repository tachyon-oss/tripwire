/**
 * A non-2xx response, or a failure to reach the server (`status === 0`).
 *
 * Mirrors the Python client's `ApiError` so the two CLIs behave identically on
 * the wire and share the same error taxonomy.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}
