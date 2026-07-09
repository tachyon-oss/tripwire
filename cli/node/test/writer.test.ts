import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { writeBlock } from "../src/placements/writer.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "tw-writer-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const BLOCK = "[profile prod]\naws_access_key_id = AKIA\naws_secret_access_key = SEK";

describe("writeBlock (-o append-or-create)", () => {
  it("creates a missing file with mode 0600 and parent dirs", () => {
    const path = join(dir, "nested", "config");
    writeBlock(path, BLOCK);
    expect(existsSync(path)).toBe(true);
    expect(readFileSync(path, "utf8")).toBe(`${BLOCK}\n`);
    // Mode check is meaningful on POSIX; the low bits must be 0600.
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("appends to an existing file with a blank-line separator, never fusing", () => {
    const path = join(dir, "config");
    writeBlock(path, "[profile a]\nkey = 1");
    writeBlock(path, "[profile b]\nkey = 2");
    expect(readFileSync(path, "utf8")).toBe(
      "[profile a]\nkey = 1\n\n[profile b]\nkey = 2\n",
    );
  });

  it("does not merge or dedup identical blocks", () => {
    const path = join(dir, "config");
    writeBlock(path, BLOCK);
    writeBlock(path, BLOCK);
    const contents = readFileSync(path, "utf8");
    expect(contents.split("[profile prod]").length - 1).toBe(2);
  });

  it("tightens an appended-to existing file to 0600 and reports mode0600", () => {
    const path = join(dir, "config");
    // A pre-existing credentials file with looser (0644) perms.
    writeFileSync(path, "[existing]\naws_access_key_id = OLD\n", { mode: 0o644 });
    const result = writeBlock(path, BLOCK);
    expect(result.mode0600).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("reports mode0600 true after creating a fresh file", () => {
    const result = writeBlock(join(dir, "fresh"), BLOCK);
    expect(result.mode0600).toBe(true);
  });
});
