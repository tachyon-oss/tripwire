/**
 * Placement delivery contract.
 *
 * DEFAULT: the rendered block goes to STDOUT with one leading + one trailing
 * newline (so `>>`/`>` compose cleanly and never fuse a header); all reporting
 * goes to STDERR.
 *
 * `-o <file>`: the CLI writes the block (append-or-create, mode 0600). POST-MINT
 * SAFETY VALVE: if the write fails AFTER the credential was minted, dump the
 * block to STDOUT with a loud stderr warning — we never lose a one-time secret.
 */
import { err, outRaw } from "../util/io.js";
import { writeBlock } from "./writer.js";

/** Print the block to stdout with the leading + trailing newline contract. */
export function deliverToStdout(block: string): void {
  outRaw(`\n${block}\n`);
}

/**
 * Write the block to `outputPath`, or fall back to stdout with a loud warning if
 * the write fails after the credential was already minted.
 */
export function deliverToFile(block: string, outputPath: string, label: string): void {
  try {
    const { mode0600 } = writeBlock(outputPath, block);
    if (mode0600) {
      err(`wrote ${label} to ${outputPath} (mode 0600)`);
    } else {
      err(
        `wrote ${label} to ${outputPath}, but could not set mode 0600; ` +
          `tighten it yourself: chmod 600 ${outputPath}`,
      );
    }
  } catch (writeError) {
    const reason = writeError instanceof Error ? writeError.message : String(writeError);
    err("");
    err(`!! could not write to ${outputPath}: ${reason}`);
    err("!! the credential was already minted and is shown below — capture it now,");
    err("!! it will NOT be shown again.");
    deliverToStdout(block);
  }
}
