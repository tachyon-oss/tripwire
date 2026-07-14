"""Interactive prompting behind a small interface, so both `auth login` and the
automatic sign-in in `Context` can ask the user a question without depending on a
real TTY. Tests inject a scripted fake; `interactive()` is what keeps the CLI
from hanging on a prompt in CI, in a pipe, or inside an agent.

Everything goes to stderr: stdout is the machine/redirect channel (a bundle zip,
a rendered credential block) and must stay clean.
"""

from __future__ import annotations

import sys
from typing import Protocol, TextIO

import click


class Prompter(Protocol):
    def interactive(self) -> bool:
        """Whether we can interactively ask the user anything (stdin is a TTY)."""

    def ask(self, question: str, default: str | None = None) -> str:
        """Ask a question. An empty answer falls back to `default`."""

    def notify(self, line: str) -> None:
        """Report a line to the user."""


class TtyPrompter:
    def __init__(self, stdin: TextIO | None = None):
        # The stream `interactive()` probes for a TTY. Injectable so that guard is
        # testable without a real terminal; see the note on `ask()`.
        self._stdin = stdin if stdin is not None else sys.stdin

    def interactive(self) -> bool:
        return self._stdin.isatty()

    def ask(self, question: str, default: str | None = None) -> str:
        # `click.prompt` reads the real stdin, and owns the Ctrl+C / Ctrl+D
        # handling that makes an aborted sign-in exit cleanly. The injected stream
        # above is the TTY probe only; it is not a general stdin substitute, and
        # tests that need to script answers inject a fake Prompter instead.
        return str(click.prompt(question, default=default, err=True)).strip()

    def notify(self, line: str) -> None:
        click.echo(line, err=True)
