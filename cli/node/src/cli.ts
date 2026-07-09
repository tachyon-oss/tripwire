#!/usr/bin/env node
/**
 * Executable entry for the `tripwire` bin. Kept separate from `index.ts` so the
 * program can be built and unit-tested without running the CLI as a side effect
 * of importing it.
 */
import { buildProgram, Session } from "./index.js";
import { err } from "./util/io.js";

async function main(): Promise<void> {
  await buildProgram(new Session()).parseAsync(process.argv);
}

main().catch((error) => {
  err(error instanceof Error ? (error.stack ?? error.message) : String(error));
  process.exitCode = 1;
});
