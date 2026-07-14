"""Interactive prompting behind a small interface, so both `auth login` and the
automatic sign-in in `Context` can ask the user a question without depending on a
real TTY. Tests inject a scripted fake; `interactive()` is what keeps the CLI
from hanging on a prompt in CI, in a pipe, or inside an agent.

Everything goes to stderr: stdout is the machine/redirect channel (a bundle zip,
a rendered credential block) and must stay clean.
"""

from __future__ import annotations

import sys
from typing import Protocol

import click


class Prompter(Protocol):
    def interactive(self) -> bool:
        """Whether we can interactively ask the user anything (stdin is a TTY)."""

    def ask(self, question: str, default: str | None = None) -> str:
        """Ask a question. An empty answer falls back to `default`."""

    def notify(self, line: str) -> None:
        """Report a line to the user."""


class TtyPrompter:
    def interactive(self) -> bool:
        return sys.stdin.isatty()

    def ask(self, question: str, default: str | None = None) -> str:
        return str(click.prompt(question, default=default, err=True)).strip()

    def notify(self, line: str) -> None:
        click.echo(line, err=True)
