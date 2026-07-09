/**
 * Canary read + lifecycle commands: `list`, `show`, `disarm`, `delete`,
 * `types`. `create` lives in `create.ts`; `api` in `api.ts`.
 */
import { type PlacementDef, PLACEMENTS, resolvePlacement } from "../placements/index.js";
import { customerTypes, resolveType, tryResolveType, type TypeEntry } from "../types/registry.js";
import { CliError, notSupported } from "../util/errors.js";
import { canaryRow, type CanarySummary, hasFired } from "../util/format.js";
import { out, printJson } from "../util/io.js";
import type { Session } from "../util/session.js";

interface ListResponse {
  canaries?: CanarySummary[];
}

export interface ListOptions {
  type?: string;
  fired?: boolean;
  in?: string;
  json?: boolean;
}

export async function runList(session: Session, opts: ListOptions): Promise<void> {
  if (opts.in) {
    notSupported(
      "--in (containment) is not yet supported by the server; canaries cannot be " +
        "filtered by parent yet.",
    );
  }
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

/**
 * One row of the `types` catalog: a raw type, or a placement nested under its
 * underlying type. Placements carry a `placement` descriptor; raw types do not.
 */
interface CatalogRow {
  /** Dotted display id (not indented; the renderer adds the indent). */
  id: string;
  /** True for a placement row (rendered indented under its underlying type). */
  nested: boolean;
  /** Human BACKING cell: real backing, or `underlying → target` for placements. */
  backingDisplay: string;
  /** Structured backing for `--json` (the underlying's real backing). */
  backingJson: string;
  firesVia: string;
  verbs: string[];
  wire: string;
  placement?: { underlying: string; target_hint: string };
}

/** The customer types, each followed by any placements nested under it. */
function catalogRows(): CatalogRow[] {
  const rows: CatalogRow[] = [];
  for (const entry of customerTypes()) {
    rows.push({
      id: entry.id,
      nested: false,
      backingDisplay: entry.backing,
      backingJson: entry.backing,
      firesVia: entry.firesVia,
      verbs: entry.verbs,
      wire: entry.wire,
    });
    for (const placement of PLACEMENTS.filter((p) => p.underlyingType === entry.id)) {
      rows.push({
        id: placement.id,
        nested: true,
        backingDisplay: `${placement.underlyingType} → ${placement.targetFile}`,
        backingJson: entry.backing,
        firesVia: entry.firesVia,
        verbs: entry.verbs,
        wire: entry.wire,
        placement: {
          underlying: placement.underlyingType,
          target_hint: placement.targetFile,
        },
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
        const record: Record<string, unknown> = {
          id: r.id,
          wire: r.wire,
          backing: r.backingJson,
          fires_via: r.firesVia,
          verbs: r.verbs,
        };
        // `placement` is present only on placement rows (absent for raw types).
        if (r.placement) record["placement"] = r.placement;
        return record;
      }),
    );
    return;
  }
  renderCatalog(rows);
}

/** Render the aligned human catalog table (dynamic column widths). */
function renderCatalog(rows: CatalogRow[]): void {
  const cells = rows.map((r) => ({
    type: (r.nested ? "  " : "") + r.id,
    backing: r.backingDisplay,
    firesVia: r.firesVia,
    verbs: r.verbs.join(" "),
  }));
  const wType = width("TYPE", cells.map((c) => c.type));
  const wBacking = width("BACKING", cells.map((c) => c.backing));
  const wFires = width("FIRES VIA", cells.map((c) => c.firesVia));
  const line = (a: string, b: string, c: string, d: string): string =>
    `${a.padEnd(wType)}  ${b.padEnd(wBacking)}  ${c.padEnd(wFires)}  ${d}`;

  out(line("TYPE", "BACKING", "FIRES VIA", "VERBS"));
  for (const c of cells) out(line(c.type, c.backing, c.firesVia, c.verbs));
  out("");
  out("indented rows are placements (CLI sugar rendered into a real config file).");
  out("run `tripwire canary types <type>` for detail.");
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
      backing: entry.backing,
      fires_via: entry.firesVia,
      verbs: entry.verbs,
      output_fields: entry.outputFields,
    });
    return;
  }
  out(entry.id);
  out(`  backing:   ${entry.backing}`);
  out(`  fires via: ${entry.firesVia}`);
  out(`  verbs:     ${entry.verbs.join(", ")}`);
  if (entry.outputFields.length > 0) {
    out(`  fields:    ${entry.outputFields.join(", ")}`);
  }
  out("");
  out(`create it with: tripwire canary create ${entry.id}`);
}

/** Explain a placement: what it creates, what it renders, its flags + example. */
function explainPlacement(placement: PlacementDef, json: boolean): void {
  const underlying = resolveType(placement.underlyingType);
  const flags = ["--name", "-o/--output"];
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
      placement: { underlying: placement.underlyingType, target_hint: placement.targetFile },
      backing: underlying.backing,
      fires_via: underlying.firesVia,
      verbs: underlying.verbs,
      flags,
      example,
    });
    return;
  }
  out(placement.id);
  out(`  placement: CLI sugar over ${underlying.id}`);
  out(`  creates:   ${underlying.id} (${underlying.backing}); fires via ${underlying.firesVia}`);
  out(`  renders:   a block for ${placement.targetFile}:`);
  for (const blockLine of sampleBlock.split("\n")) out(`               ${blockLine}`);
  out(`  flags:     ${flags.join(", ")}`);
  out(`  verbs:     ${underlying.verbs.join(", ")}`);
  out("");
  out(`example: ${example}`);
}

// Re-exported so the command wiring can reference type metadata if needed.
export type { TypeEntry };
