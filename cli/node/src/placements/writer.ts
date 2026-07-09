/**
 * The `-o/--output` file writer for placements: append-or-create, NO merge, NO
 * dedup. A missing file is created with its parent dirs and mode
 * 0600; an existing file is appended to with a blank-line separator so blocks
 * never fuse.
 */
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

/**
 * Write `block` (no trailing newline) to `path`, then tighten the file to mode
 * 0600 (it holds credentials).
 *
 * - missing file: create parent dirs, write `block\n`, mode 0600.
 * - existing file: append `\n{block}\n` so the block is separated from prior
 *   content and never fuses with a file lacking a trailing newline.
 *
 * The WRITE throws on any filesystem failure so the caller's post-mint safety
 * valve can dump the one-time secret to stdout instead of losing it. The chmod
 * is best-effort: returns `{ mode0600 }` so the caller can report truthfully
 * (an append to a user's existing file may not be chmod-able by us).
 */
export function writeBlock(path: string, block: string): { mode0600: boolean } {
  const exists = existsSync(path);
  if (!exists) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${block}\n`, { mode: 0o600 });
  } else {
    const nonEmpty = statSync(path).size > 0;
    appendFileSync(path, nonEmpty ? `\n${block}\n` : `${block}\n`);
  }
  try {
    chmodSync(path, 0o600);
    return { mode0600: true };
  } catch {
    return { mode0600: false };
  }
}
