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

export interface Prompter {
  /** Whether we can interactively ask the user anything (stdin is a TTY). */
  interactive(): boolean;
  /** Ask a question. An empty answer falls back to `def`. */
  ask(question: string, def?: string | null): Promise<string>;
  /** Report a line to the user. */
  notify(line: string): void;
}

export class TtyPrompter implements Prompter {
  interactive(): boolean {
    return Boolean(process.stdin.isTTY);
  }

  async ask(question: string, def?: string | null): Promise<string> {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      const suffix = def ? ` [${def}]` : "";
      const answer = (await rl.question(`${question}${suffix}: `)).trim();
      return answer || def || "";
    } finally {
      rl.close();
    }
  }

  notify(line: string): void {
    process.stderr.write(`${line}\n`);
  }
}
