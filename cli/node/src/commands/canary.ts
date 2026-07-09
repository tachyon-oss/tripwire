/**
 * Canary read + lifecycle commands: `list`, `show`, `disarm`, `delete`,
 * `types`. `create` lives in `create.ts`; `api` in `api.ts`.
 */
import { type PlacementDef, PLACEMENTS, resolvePlacement } from "../placements/index.js";
import { customerTypes, resolveType, tryResolveType, type TypeEntry } from "../types/registry.js";
import { CliError } from "../util/errors.js";
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
  const response = (await session.authedClient().listCanaries()) as ListResponse;
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
  const canary = (await session.authedClient().getCanary(id)) as CanarySummary;
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
  out(`actions: tripwire canary disarm ${id}  |  tripwire canary delete ${id}`);
}

export async function runDisarm(session: Session, id: string): Promise<void> {
  printJson(await session.authedClient().deactivateCanary(id));
}

export async function runDelete(session: Session, id: string): Promise<void> {
  printJson(await session.authedClient().deleteCanary(id));
}

export interface TypesOptions {
  json?: boolean;
}

/** Plain, user-facing one-liner per type (no internal backing/fire details). */
const TYPE_SUMMARY: Record<string, string> = {
  "aws.access_key": "AWS access key",
  "github.token": "GitHub token",
  "database.credentials": "database login",
  "web.login": "fake login page + password",
  "web.cookie": "browser session cookie",
  "k8s.config": "Kubernetes kubeconfig",
};

function typeSummary(id: string): string {
  return TYPE_SUMMARY[id] ?? id;
}

function placementSummary(p: PlacementDef): string {
  return `${typeSummary(p.underlyingType)}, rendered into ${p.targetFile}`;
}

/** One row of the `types` catalog: a raw type, or a placement nested under it. */
interface CatalogRow {
  id: string;
  nested: boolean;
  summary: string;
  wire: string;
  placement?: { underlying: string; target_hint: string };
}

/** The customer types, each followed by any placements nested under it. */
function catalogRows(): CatalogRow[] {
  const rows: CatalogRow[] = [];
  for (const entry of customerTypes()) {
    rows.push({ id: entry.id, nested: false, summary: typeSummary(entry.id), wire: entry.wire });
    for (const placement of PLACEMENTS.filter((p) => p.underlyingType === entry.id)) {
      rows.push({
        id: placement.id,
        nested: true,
        summary: placementSummary(placement),
        wire: entry.wire,
        placement: { underlying: placement.underlyingType, target_hint: placement.targetFile },
      });
    }
  }
  return rows;
}

/** `types` (catalog) / `types <type>` (explain one). */
export function runTypes(arg: string | undefined, opts: TypesOptions): void {
  if (arg) {
    explainType(arg, opts.json ?? false);
    return;
  }
  const rows = catalogRows();
  if (opts.json) {
    printJson(
      rows.map((r) => {
        const record: Record<string, unknown> = { id: r.id, wire: r.wire, summary: r.summary };
        // `placement` is present only on placement rows (absent for raw types).
        if (r.placement) record["placement"] = r.placement;
        return record;
      }),
    );
    return;
  }
  renderCatalog(rows);
}

/** Render the aligned human catalog table: TYPE + a plain description. */
function renderCatalog(rows: CatalogRow[]): void {
  const cells = rows.map((r) => ({ type: (r.nested ? "  " : "") + r.id, summary: r.summary }));
  const wType = width("TYPE", cells.map((c) => c.type));
  const line = (a: string, b: string): string => `${a.padEnd(wType)}  ${b}`;

  out(line("TYPE", "WHAT IT IS"));
  for (const c of cells) out(line(c.type, c.summary));
  out("");
  out("Every canary alerts you the moment its credential is used.");
  out("Indented types render a ready-to-use config block for the file shown.");
}

function width(header: string, values: string[]): number {
  return Math.max(header.length, ...values.map((v) => v.length));
}

/** Explain one type or placement; error on an unknown or internal id. */
function explainType(arg: string, json: boolean): void {
  const placement = resolvePlacement(arg);
  if (placement) {
    explainPlacement(placement, json);
    return;
  }
  const entry = tryResolveType(arg);
  if (!entry || entry.visibility !== "customer") {
    throw new CliError(
      `unknown canary type "${arg}". run \`tripwire canary types\` to list types.`,
    );
  }
  if (json) {
    printJson({
      id: entry.id,
      wire: entry.wire,
      summary: typeSummary(entry.id),
      fields: entry.outputFields,
    });
    return;
  }
  out(entry.id);
  out(`  ${typeSummary(entry.id)}; alerts the moment it is used.`);
  out("");
  out(`create it with: tripwire canary create ${entry.id}`);
}

/** Explain a placement: what it creates, what it renders, its flags + example. */
function explainPlacement(placement: PlacementDef, json: boolean): void {
  const underlying = resolveType(placement.underlyingType);
  const flags = ["-o/--output"];
  const example = `tripwire canary create ${placement.id} >> ${placement.targetFile}`;
  const sampleBlock = placement.render("<name>", {
    accessKeyId: "AKIA…",
    secretAccessKey: "…",
    region: "us-east-1",
  });

  if (json) {
    printJson({
      id: placement.id,
      wire: underlying.wire,
      summary: placementSummary(placement),
      placement: { underlying: placement.underlyingType, target_hint: placement.targetFile },
      flags,
      example,
    });
    return;
  }
  out(placement.id);
  out(`  ${placementSummary(placement)}:`);
  for (const blockLine of sampleBlock.split("\n")) out(`      ${blockLine}`);
  out(`  flags: ${flags.join(", ")}`);
  out("");
  out(`example: ${example}`);
}

// Re-exported so the command wiring can reference type metadata if needed.
export type { TypeEntry };
