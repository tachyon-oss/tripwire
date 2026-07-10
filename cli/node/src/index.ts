/**
 * `tripwire` — command-line client for Tripwire security canaries.
 *
 * Noun-first grammar:
 *   tripwire login | logout | status
 *   tripwire canary create|list|show|delete
 *   tripwire bundle download
 * Single canonical names only — no command aliases and no back-compat surface.
 *
 * This module is side-effect free: it exports `buildProgram` (and `Session`)
 * for tests and library use. The executable entry is `cli.ts`.
 */
import { readFileSync } from "node:fs";

import { Command } from "commander";

import { runLogin, runLogout } from "./commands/auth.js";
import { runBundleDownload } from "./commands/bundle.js";
import { runDelete, runList, runShow } from "./commands/canary.js";
import { runCreate } from "./commands/create.js";
import { runStatus } from "./commands/status.js";
import { PLACEMENTS } from "./placements/index.js";
import { customerTypes } from "./types/registry.js";
import { action } from "./util/errors.js";
import { Session } from "./util/session.js";

export { Session };

function readVersion(): string {
  try {
    const url = new URL("../package.json", import.meta.url);
    const pkg = JSON.parse(readFileSync(url, "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/** Comma-separated creatable ids (customer types + placements), for `create` help. */
function creatableTypeList(): string {
  return [...customerTypes().map((e) => e.id), ...PLACEMENTS.map((p) => p.id)].join(", ");
}

export function buildProgram(session: Session): Command {
  const program = new Command();
  program
    .name("tripwire")
    .description("Create and manage Tripwire security canaries.")
    .version(readVersion(), "-v, --version")
    .showHelpAfterError();

  // ----- auth / session -----
  program
    .command("login")
    .description("log in with an emailed sign-in code and cache a token")
    .option("--email <addr>", "email address to sign in with")
    .action(action(async (opts: { email?: string }) => runLogin(session, opts)));

  program
    .command("logout")
    .description("forget the cached token")
    .action(action(() => runLogout(session)));

  program
    .command("status")
    .description("cross-object dashboard: identity, counts, fired-first canaries")
    .option("--watch", "re-poll and redraw every few seconds")
    .option("--json", "emit verbatim server JSON")
    .action(
      action(async (opts: { watch?: boolean; json?: boolean }) =>
        runStatus(session, opts),
      ),
    );

  // ----- canary group -----
  const canary = program.command("canary").description("create and manage canaries");

  canary
    .command("create")
    .argument("[type]", `canary type, one of: ${creatableTypeList()}`)
    .description("create a canary; the credential is shown once, at creation")
    .option("--note <note>", "your own note to remember where you placed it")
    .option("-o, --output <file>", "write the credential to a file instead of stdout")
    .action(
      action(
        async (
          type: string | undefined,
          opts: {
            note?: string;
            output?: string;
          },
        ) =>
          runCreate(session, {
            type,
            note: opts.note,
            output: opts.output,
          }),
      ),
    );

  canary
    .command("list")
    .description("list your canaries")
    .option("--type <type>", "filter by type")
    .option("--fired", "only canaries that have fired")
    .option("--json", "emit verbatim server JSON")
    .action(
      action(async (opts: { type?: string; fired?: boolean; json?: boolean }) =>
        runList(session, opts),
      ),
    );

  canary
    .command("show")
    .argument("<id>", "canary id")
    .description("show one canary, including fire hits")
    .option("--json", "emit verbatim server JSON")
    .action(action(async (id: string, opts: { json?: boolean }) => runShow(session, id, opts)));

  canary
    .command("delete")
    .argument("<id>", "canary id")
    .description("delete a canary")
    .action(action(async (id: string) => runDelete(session, id)));

  // ----- bundle group (public endpoints, but the CLI still requires login) -----
  const bundle = program
    .command("bundle")
    .description("download bait bundles");

  bundle
    .command("download")
    .argument("[id]", "bundle id (omit to issue a fresh bundle for you first)")
    .description("download a bundle and extract it; with no id, issue a fresh bundle for you first")
    .option(
      "-o, --output <path>",
      "extract dir (default ./<name>/); with --zip, the .zip file; '-' streams the zip to stdout",
    )
    .option("--zip", "keep the raw .zip archive instead of extracting it")
    .action(
      action(async (id: string | undefined, opts: { output?: string; zip?: boolean }) =>
        runBundleDownload(session, id, opts),
      ),
    );

  return program;
}
