/**
 * Vendored type registry — the single source of type knowledge in the CLI, and
 * the swap-seam for a future server-side `GET /types`.
 *
 * The naming rule: LEFT of the dot = provider/surface namespace; RIGHT of the
 * dot = the artifact you receive. Realness lives in the BACKING field, not the
 * id.
 *
 * WIRE CONTRACT: the wire speaks snake (`POST /canary {"type":"aws_access_key"}`)
 * until a server registry lands. The CLI accepts ONLY the canonical dotted ids
 * as user input and TRANSLATES to the snake `wire` id on the way out; it maps the
 * snake ids the server returns back to dotted for display. `--json` output stays
 * verbatim server truth (snake), so scripts never break.
 */
import { CliError } from "../util/errors.js";

export type Visibility = "customer" | "unreleased" | "operator";

export interface TypeEntry {
  /** Dotted canonical id, e.g. `aws.access_key` — the only accepted input id. */
  id: string;
  /** Snake wire id sent to `POST /canary`, e.g. `aws_access_key`. */
  wire: string;
  /** How the underlying credential is backed (realness lives here, not in id). */
  backing: string;
  /** How a fire is detected. */
  firesVia: string;
  /**
   * The output keys the create response inlines for this type, mirroring
   * `_RESPONSE_BY_TYPE` in `api/v1/canary.py`. Used to render the human create
   * output; `--json` passes server truth through untouched.
   */
  outputFields: string[];
  /** Lifecycle verbs this type supports today (for the `types` VERBS column). */
  verbs: string[];
  /** Only `customer` types appear in create input and `types` output. */
  visibility: Visibility;
  /**
   * Read-timeout floor for this type's synchronous create, in seconds. Replaces
   * the CLI's old hardcoded 240s `CREATE_READ_TIMEOUT`; every type keeps the
   * 240s floor today because the server waits up to 180s before giving up.
   */
  waitSeconds: number;
}

/**
 * The create read-timeout floor, in seconds. Must stay above the server's ~180s
 * synchronous create wait window so the client never abandons a create whose
 * one-time reveal the server is still preparing.
 */
export const DEFAULT_WAIT_SECONDS = 240;

/** The lifecycle verbs the object model supports today (kubectl-style column). */
const LIFECYCLE_VERBS = ["disarm", "delete"];

export const REGISTRY: TypeEntry[] = [
  {
    id: "aws.access_key",
    wire: "aws_access_key",
    backing: "real IAM key",
    firesVia: "CloudTrail",
    outputFields: ["access_key_id", "secret_access_key", "region"],
    verbs: LIFECYCLE_VERBS,
    visibility: "customer",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
  {
    id: "github.token",
    wire: "github_pat",
    backing: "real PAT/OAuth token",
    firesVia: "audit stream",
    outputFields: ["raw_token"],
    verbs: LIFECYCLE_VERBS,
    visibility: "customer",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
  {
    id: "anthropic.api_key",
    wire: "anthropic_api_key",
    backing: "real console API key",
    firesVia: "rate-limit telemetry",
    outputFields: ["raw_key"],
    verbs: LIFECYCLE_VERBS,
    visibility: "unreleased",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
  {
    id: "database.credentials",
    wire: "postgres_login",
    backing: "Tripwire TCP edge",
    firesVia: "connect",
    outputFields: [
      "database_url",
      "url",
      "host",
      "port",
      "database",
      "username",
      "password",
      "sslmode",
    ],
    verbs: LIFECYCLE_VERBS,
    visibility: "customer",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
  {
    id: "web.login",
    wire: "web_login_credential",
    backing: "Tripwire HTTP edge",
    firesVia: "credential submit",
    outputFields: ["url", "username", "password"],
    verbs: LIFECYCLE_VERBS,
    visibility: "customer",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
  {
    id: "web.cookie",
    wire: "browser_session_cookie",
    backing: "Tripwire HTTP edge",
    firesVia: "cookie presented",
    outputFields: [
      "url",
      "cookie_name",
      "cookie_value",
      "cookie_domain",
      "cookie_path",
    ],
    verbs: LIFECYCLE_VERBS,
    visibility: "customer",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
  {
    id: "k8s.config",
    wire: "kubernetes_kubeconfig",
    backing: "Tripwire k8s edge",
    firesVia: "API use",
    outputFields: [
      "server",
      "cluster_name",
      "user_name",
      "bearer_token",
      "token",
      "kubeconfig",
    ],
    verbs: LIFECYCLE_VERBS,
    visibility: "customer",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
  // Internal-only: kept so the snake ids the server returns still map to a dotted
  // display id, but hidden from the CLI, from `types`, and from create input.
  {
    id: "dns.label",
    wire: "dns_label",
    backing: "operator DNS zone",
    firesVia: "DNS query",
    outputFields: ["fqdn", "qtype"],
    verbs: LIFECYCLE_VERBS,
    visibility: "operator",
    waitSeconds: DEFAULT_WAIT_SECONDS,
  },
];

export class UnknownTypeError extends CliError {
  constructor(input: string) {
    super(
      `unknown canary type "${input}". run \`tripwire canary types\` to see the ` +
        `available types.`,
    );
    this.name = "UnknownTypeError";
  }
}

/** Accepted create input: canonical dotted id -> entry, customer types only. */
const INPUT_LOOKUP: Map<string, TypeEntry> = new Map(
  REGISTRY.filter((e) => e.visibility === "customer").map((e) => [e.id, e]),
);

/** Reverse map for display: every wire id (customer + operator) -> its entry. */
const WIRE_LOOKUP: Map<string, TypeEntry> = new Map(
  REGISTRY.map((e) => [e.wire, e]),
);

/** Resolve a create-input type id. Only the canonical dotted ids are accepted. */
export function resolveType(input: string): TypeEntry {
  const entry = INPUT_LOOKUP.get(input.trim().toLowerCase());
  if (!entry) throw new UnknownTypeError(input);
  return entry;
}

/** `resolveType` that returns `undefined` instead of throwing. */
export function tryResolveType(input: string): TypeEntry | undefined {
  return INPUT_LOOKUP.get(input.trim().toLowerCase());
}

/** The customer-facing types, in registry order (for `types` listing). */
export function customerTypes(): TypeEntry[] {
  return REGISTRY.filter((e) => e.visibility === "customer");
}

/** Dotted display id for a wire type, falling back to the wire value itself. */
export function dottedForWire(wire: string): string {
  const entry = WIRE_LOOKUP.get(wire.toLowerCase());
  return entry ? entry.id : wire;
}
