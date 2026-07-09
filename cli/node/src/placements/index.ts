/**
 * AWS placement registry — CLI-layer sugar over `aws.access_key`.
 *
 * A placement mints the underlying canary via `POST /canary`, then
 * renders the returned one-time credential into a real config-file format. The
 * stored row is just the underlying type; the placement affects only create-time
 * output. Renderers are self-contained here with no external dependencies.
 */
import { type AwsKeyFields, renderAwsCredentials, renderAwsProfile } from "./render.js";

export interface PlacementDef {
  /** Placement id, e.g. `aws.profile`. */
  id: string;
  /** Dotted id of the underlying canary type this mints. */
  underlyingType: string;
  /** Target file this block is meant for. */
  targetFile: string;
  /** Render the returned credential into the placement's config block. */
  render(name: string, fields: AwsKeyFields): string;
}

export const PLACEMENTS: PlacementDef[] = [
  {
    id: "aws.profile",
    underlyingType: "aws.access_key",
    targetFile: "~/.aws/config",
    render: renderAwsProfile,
  },
  {
    id: "aws.credentials",
    underlyingType: "aws.access_key",
    targetFile: "~/.aws/credentials",
    render: renderAwsCredentials,
  },
];

const BY_ID = new Map(PLACEMENTS.map((p) => [p.id.toLowerCase(), p]));

/** The placement for `id`, or `undefined` if `id` is not a placement. */
export function resolvePlacement(id: string): PlacementDef | undefined {
  return BY_ID.get(id.trim().toLowerCase());
}
