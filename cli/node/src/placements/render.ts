/**
 * Self-contained AWS placement renderers with no external dependencies.
 *
 * Each renderer returns the block text with NO leading or trailing newline; the
 * delivery layer (`deliver.ts`) owns the one-leading + one-trailing-newline
 * stdout contract and the `-o` file separators.
 */

export interface AwsKeyFields {
  accessKeyId: string;
  secretAccessKey: string;
  region?: string | null;
}

/**
 * `[profile <name>]` block for `~/.aws/config`. Keys: aws_access_key_id,
 * aws_secret_access_key, region. The region line is included only when present.
 */
export function renderAwsProfile(name: string, fields: AwsKeyFields): string {
  const lines = [
    `[profile ${name}]`,
    `aws_access_key_id = ${fields.accessKeyId}`,
    `aws_secret_access_key = ${fields.secretAccessKey}`,
  ];
  if (fields.region) lines.push(`region = ${fields.region}`);
  return lines.join("\n");
}

/**
 * `[<name>]` block for `~/.aws/credentials`. Same keys as the profile block but
 * WITHOUT the region line (region belongs in `~/.aws/config`, not credentials).
 */
export function renderAwsCredentials(name: string, fields: AwsKeyFields): string {
  return [
    `[${name}]`,
    `aws_access_key_id = ${fields.accessKeyId}`,
    `aws_secret_access_key = ${fields.secretAccessKey}`,
  ].join("\n");
}
