/**
 * Interactive prompting behind a small interface, so both `auth login` and the
 * automatic sign-in in `Session` can ask the user a question without depending
 * on a real TTY. Tests inject a scripted fake; `interactive()` is what keeps the
 * CLI from hanging on a prompt in CI, in a pipe, or inside an agent.
 *
 * Everything goes to stderr: stdout is the machine/redirect channel (a bundle
 * zip, a rendered credential block) and must stay clean.
 */
import { createInterface } from "node:readline/promises";

import { CliError } from "./errors.js";

export interface Prompter {
  /** Whether we can interactively ask the user anything (stdin is a TTY). */
  interactive(): boolean;
  /** Ask a question. An empty answer falls back to `def`. */
  ask(question: string, def?: string | null): Promise<string>;
  /** Report a line to the user. */
  notify(line: string): void;
}

export class TtyPrompter implements Prompter {
  /** The input stream is injectable so `interactive()` is testable without a
   *  real terminal; it defaults to the process's stdin. */
  constructor(private readonly input: NodeJS.ReadStream = process.stdin) {}

  interactive(): boolean {
    return Boolean(this.input.isTTY);
  }

  async ask(question: string, def?: string | null): Promise<string> {
    const rl = createInterface({ input: this.input, output: process.stderr });
    // Ctrl+C closes the interface, which rejects the pending question below.
    rl.on("SIGINT", () => rl.close());
    try {
      const suffix = def ? ` [${def}]` : "";
      const answer = (await rl.question(`${question}${suffix}: `)).trim();
      return answer || def || "";
    } catch {
      // Ctrl+C / Ctrl+D at the prompt. Sign-in is often something we started on
      // the user's behalf, not something they asked for, so backing out of it is
      // an ordinary choice: exit cleanly rather than dumping a readline stack.
      throw new CliError("sign-in cancelled.");
    } finally {
      rl.close();
    }
  }

  notify(line: string): void {
    process.stderr.write(`${line}\n`);
  }
}
