"""Command-line client for Tripwire canaries.

Noun-first grammar (single canonical names only; no aliases, no back-compat):

  tripwire auth login | auth logout | auth status
  tripwire status
  tripwire canary create <type> [--note <s>] [-o <file>]
  tripwire canary list [--type <t>] [--fired] [--json]
  tripwire canary show <id> [--json]
  tripwire canary delete <id>
  tripwire bundle download [<id>] [-o <path>] [--zip]

Any command that needs auth signs you in first when it has a TTY; without one it
fails with a "run `tripwire auth login`" message rather than hanging on a prompt.

`auth login` does not take a server flag. The server is resolved as
$TRIPWIRE_SERVER, then the last-used cached server, then the default; set
$TRIPWIRE_SERVER to point at a self-hosted or test server.
"""

from __future__ import annotations

import functools
import io
import json
import os
import re
import time
import urllib.parse
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

from tripwire_cli import credentials
from tripwire_cli.client import ApiClient, ApiError
from tripwire_cli.prompt import Prompter, TtyPrompter

DEFAULT_SERVER = credentials.DEFAULT_SERVER

# How many times to re-prompt for the emailed code before giving up. Re-prompts
# never re-call /auth/login/start (which is rate-limited); they re-submit a new
# code against the same challenge.
EMAIL_CODE_ATTEMPTS = 3


# --- type registry ----------------------------------------------------------
#
# LEFT of the dot = provider/surface namespace; RIGHT of the dot = the artifact
# you receive. The wire speaks snake (`POST /canary {"type":"aws_access_key"}`);
# the CLI accepts ONLY the canonical dotted ids as user input and TRANSLATES to
# the snake ``wire`` id on the way out, mapping snake ids the server returns back
# to dotted for display. `--json` output stays verbatim server truth (snake).

# Read-timeout floor for a synchronous create, in seconds. Must stay above the
# server's ~180s create wait window so the client never abandons a create whose
# one-time reveal the server is still preparing.
DEFAULT_WAIT_SECONDS = 240.0


@dataclass(frozen=True)
class TypeEntry:
    # Dotted canonical id, e.g. ``aws.access_key`` -- the only accepted input id.
    id: str
    # Snake wire id sent to ``POST /canary``, e.g. ``aws_access_key``.
    wire: str
    # The output keys the create response inlines for this type; used to render
    # the human create output. ``--json`` passes server truth through untouched.
    output_fields: list[str]
    # Only ``customer`` types appear in create input.
    visibility: str
    wait_seconds: float = DEFAULT_WAIT_SECONDS


REGISTRY: list[TypeEntry] = [
    TypeEntry("aws.access_key", "aws_access_key",
              ["access_key_id", "secret_access_key", "region"], "customer"),
    TypeEntry("github.token", "github_pat", ["raw_token"], "customer"),
    TypeEntry("anthropic.api_key", "anthropic_api_key", ["raw_key"], "unreleased"),
    TypeEntry("database.credentials", "postgres_login",
              ["database_url", "url", "host", "port", "database", "username",
               "password", "sslmode"], "customer"),
    TypeEntry("web.login", "web_login_credential",
              ["url", "username", "password"], "customer"),
    TypeEntry("web.cookie", "browser_session_cookie",
              ["url", "cookie_name", "cookie_value", "cookie_domain",
               "cookie_path"], "customer"),
    TypeEntry("k8s.config", "kubernetes_kubeconfig",
              ["server", "cluster_name", "user_name", "bearer_token", "token",
               "kubeconfig"], "customer"),
    # Internal type, hidden from the CLI and from create input.
    TypeEntry("dns.label", "dns_label", ["fqdn", "qtype"], "internal"),
]

_INPUT_LOOKUP = {e.id: e for e in REGISTRY if e.visibility == "customer"}
_WIRE_LOOKUP = {e.wire: e for e in REGISTRY}


class UnknownTypeError(click.ClickException):
    def __init__(self, given: str):
        super().__init__(
            f'unknown canary type "{given}". run '
            "`tripwire canary create --help` to see the available types."
        )


def resolve_type(given: str) -> TypeEntry:
    """Resolve a create-input type id. Only the canonical dotted ids are
    accepted; an unknown id raises a friendly error."""
    entry = _INPUT_LOOKUP.get(given.strip().lower())
    if entry is None:
        raise UnknownTypeError(given)
    return entry


def dotted_for_wire(wire: str) -> str:
    """Dotted display id for a wire type, falling back to the wire value."""
    entry = _WIRE_LOOKUP.get((wire or "").lower())
    return entry.id if entry else wire


def customer_type_ids() -> list[str]:
    return [e.id for e in REGISTRY if e.visibility == "customer"]


# --- AWS placements ---------------------------------------------------------
#
# CLI-layer sugar over ``aws.access_key``: a placement mints the underlying
# canary, then renders the returned one-time credential into a real config-file
# block. The stored row is just the underlying type; the placement affects only
# create-time output. The profile/label name is generated by the backend.


def render_aws_profile(name: str, access_key_id: str, secret: str, region: str) -> str:
    """``[profile <name>]`` block for ``~/.aws/config`` (with region if present)."""
    lines = [
        f"[profile {name}]",
        f"aws_access_key_id = {access_key_id}",
        f"aws_secret_access_key = {secret}",
    ]
    if region:
        lines.append(f"region = {region}")
    return "\n".join(lines)


def render_aws_credentials(name: str, access_key_id: str, secret: str, region: str) -> str:
    """``[<name>]`` block for ``~/.aws/credentials`` (no region line)."""
    return "\n".join([
        f"[{name}]",
        f"aws_access_key_id = {access_key_id}",
        f"aws_secret_access_key = {secret}",
    ])


@dataclass(frozen=True)
class PlacementDef:
    id: str
    underlying_type: str
    render: Callable[[str, str, str, str], str]


PLACEMENTS: list[PlacementDef] = [
    PlacementDef("aws.profile", "aws.access_key", render_aws_profile),
    PlacementDef("aws.credentials", "aws.access_key", render_aws_credentials),
]

_PLACEMENT_LOOKUP = {p.id: p for p in PLACEMENTS}


def resolve_placement(given: str) -> PlacementDef | None:
    return _PLACEMENT_LOOKUP.get(given.strip().lower())


# The creatable ids (customer types + placements), for `create` help.
CREATABLE_TYPES = customer_type_ids() + [p.id for p in PLACEMENTS]


# --- format helpers ---------------------------------------------------------


def _has_fired(canary: dict[str, Any]) -> bool:
    return bool(canary.get("last_used_at"))


def _armed_word(status: str | None) -> str:
    if status == "active":
        return "armed"
    if status == "inactive":
        return "disarmed"
    return status or "unknown"


def _identity_line(creds: credentials.Credentials) -> str:
    parts = [creds.user_id]
    if creds.email:
        parts.append(creds.email)
    # Surface the server only for a non-default (self-hosted / test) target.
    if creds.server:
        parts.append(creds.server)
    return "  ".join(parts)


def _canary_row(canary: dict[str, Any]) -> str:
    dotted = dotted_for_wire(str(canary.get("type", "")))
    if _has_fired(canary):
        state = f"used {canary.get('last_used_at')}"
    else:
        state = _armed_word(canary.get("status"))
    memo = f"  {canary['memo']}" if canary.get("memo") else ""
    return f"  {canary.get('id')}  {dotted}  {state}{memo}"


# --- io ---------------------------------------------------------------------


def _out(line: str = "") -> None:
    click.echo(line)


def _err(line: str = "") -> None:
    click.echo(line, err=True)


def _print_json(value: Any) -> None:
    click.echo(json.dumps(value, indent=2))


# --- session ----------------------------------------------------------------


def resolve_login_server(env: dict[str, str], cached: str | None) -> str:
    """Server URL for `login`: env override, else the last-used cached server,
    else the default."""
    return env.get("TRIPWIRE_SERVER") or cached or DEFAULT_SERVER


class Context:
    """Shared state for the commands: the credential store, a factory that builds
    an :class:`ApiClient` from a server URL and optional token, and the prompt
    channel. All three are injectable so tests can supply fakes.

    This is the CLI's single authentication choke point: every authenticated
    command goes through :meth:`authed_client`, so automatic sign-in lives here
    and nowhere else."""

    def __init__(
        self,
        store: credentials.CredentialStore | None = None,
        client_factory: Callable[[str, str | None], ApiClient] | None = None,
        prompter: Prompter | None = None,
    ):
        self.store = store or credentials.default_store()
        self._client_factory = client_factory or (
            lambda server, token=None: ApiClient(base_url=server, token=token)
        )
        self.prompter = prompter or TtyPrompter()

    def client(self, server: str, token: str | None = None) -> ApiClient:
        return self._client_factory(server, token)

    def require_credentials(self) -> credentials.Credentials:
        """The credentials an authenticated command runs on: the cached token when
        it is usable, otherwise an interactive sign-in performed right now.
        Without a TTY there is no way to ask for a code, so fail fast rather than
        hang (CI, a pipe, or an agent all land here)."""
        cached = self.store.try_load()
        if cached is not None and not cached.is_expired():
            return cached

        if not self.prompter.interactive():
            raise click.ClickException(
                "not logged in. run `tripwire auth login` first.\n"
                "(no TTY available to prompt for a sign-in code)"
            )
        self.prompter.notify(
            "your session has expired. signing you in again."
            if cached is not None
            else "not logged in. signing you in first."
        )
        return self.log_in()

    def log_in(self, email: str | None = None) -> credentials.Credentials:
        """Run the interactive email-code login and cache the result."""
        server = resolve_login_server(dict(os.environ), self.cached_server())
        creds = _email_login(
            self.client(server),
            server,
            self.cached_login_email(),
            email=email,
            prompter=self.prompter,
        )
        self.store.save(creds)
        return creds

    def authed_client(self) -> ApiClient:
        creds = self.require_credentials()
        return self.client(creds.resolved_server(), creds.access_token)

    def current_credentials(self) -> credentials.Credentials | None:
        """The cached credentials, or None. Never prompts: this is what `auth
        status` reports on, and asking for a sign-in code there would be absurd."""
        return self.store.try_load()

    def cached_server(self) -> str | None:
        # try_load, not load: an unusable cache is exactly the case that sends us
        # here to log in, so it must not resurface as a parse error mid-login.
        cached = self.store.try_load()
        return cached.server if cached is not None else None

    def cached_login_email(self) -> str | None:
        """The email from a prior login (the local cache) as the prompt default,
        else None. Never derived from git or any other local identity."""
        cached = self.store.try_load()
        return cached.email if cached is not None else None


# --- errors -----------------------------------------------------------------

# Substrings the server leaks on a 401 when the cached token is malformed or
# undecodable. These are opaque to users, so we map them to a plain "session
# expired" message instead of echoing the raw detail.
_EXPIRED_SESSION_MARKERS = (
    "invalid header padding",
    "invalid token",
    "not enough segments",
    "signature",
    "expired",
    "decrypt",
)


def _unauthorized_message(detail: str) -> str:
    """User-facing text for a 401. Raw token/header decode errors (e.g. "Invalid
    header padding") are meaningless to users, so map them to a clear
    session-expired prompt; otherwise keep the server detail and append a hint."""
    lowered = detail.lower()
    if any(marker in lowered for marker in _EXPIRED_SESSION_MARKERS):
        return "session expired; run `tripwire auth login`"
    return f"401: {detail}\nhint: run `tripwire auth login`"


def _handle_errors(func):
    """Translate API/credential errors into a clean CLI error and exit code."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ApiError as exc:
            if exc.status == 401:
                raise click.ClickException(_unauthorized_message(exc.detail)) from exc
            raise click.ClickException(f"{exc.status}: {exc.detail}") from exc
        except (credentials.NoCredentialsError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc

    return wrapper


# --- top-level group --------------------------------------------------------


@click.group()
@click.version_option(package_name="tripwire-cli", prog_name="tripwire")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Create and manage Tripwire security canaries."""
    ctx.obj = ctx.obj or Context()


# --- auth group -------------------------------------------------------------


@cli.group()
def auth() -> None:
    """Log in, log out, and check your session."""


@auth.command("login")
@click.option("--email", help="email address to sign in with")
@click.pass_obj
@_handle_errors
def auth_login(obj: Context, email: str | None) -> None:
    """Log in with an emailed sign-in code and cache a token.

    Sends a 6-digit code to your email (`--email`, else the address from your
    last login, else prompted) and asks you to enter it. Login is interactive:
    there is no password login and no non-interactive code flag.
    """
    creds = obj.log_in(email=email)
    _out(f"logged in as {creds.user_id}")


def _email_login(
    client: ApiClient,
    server: str,
    default_email: str | None,
    *,
    email: str | None = None,
    prompter: Prompter,
) -> credentials.Credentials:
    """Emailed-code login.

    Calls /auth/login/start once (it is rate-limited), then prompts for the
    6-digit code, re-prompting in-band on an invalid/expired code without
    re-calling start. ``email`` (e.g. from ``--email``) skips the email prompt.
    """
    email = email or prompter.ask("email", default_email)
    if not email:
        raise click.ClickException("an email address is required to log in.")

    _start_email_login(client, email)
    prompter.notify(f"sent a 6-digit sign-in code to {email}; check your inbox.")
    last_error: ApiError | None = None
    for attempt in range(EMAIL_CODE_ATTEMPTS):
        entered = prompter.ask("code")
        try:
            response = _exchange_code(client, email, entered)
        except ApiError as exc:
            if exc.status == 400 and exc.detail == "invalid_or_expired_code":
                last_error = exc
                remaining = EMAIL_CODE_ATTEMPTS - attempt - 1
                if remaining:
                    prompter.notify(
                        f"invalid or expired code; {remaining} attempt(s) left."
                    )
                continue
            raise
        return _credentials_from_login(server, response, email=email)
    # Exhausted the re-prompt budget; surface the last invalid-code error.
    raise last_error if last_error is not None else ApiError(400, "invalid_or_expired_code")


def _start_email_login(client: ApiClient, email: str) -> None:
    """Send the sign-in code, turning the rate-limit 429 into a friendly,
    actionable message instead of a raw ``429: rate_limited``."""
    try:
        client.login_start(email)
    except ApiError as exc:
        if exc.status == 429:
            raise click.ClickException(
                "too many login attempts from this network; wait ~10 minutes and "
                "try `tripwire auth login` again."
            ) from exc
        raise


def _exchange_code(client: ApiClient, email: str, code: str) -> dict[str, Any]:
    """Exchange a code for a token. A server-side 5xx here is the dangerous case:
    the code may already have been consumed, so retrying the same code is futile
    and silently re-sending one would burn the rate-limited start. Surface a
    clear message and have the user re-run `tripwire auth login` for a fresh code."""
    try:
        return client.login_with_code(email, code)
    except ApiError as exc:
        if exc.status >= 500:
            raise click.ClickException(
                "the server errored while verifying your code "
                f"({exc.status}: {exc.detail}); your code may already be spent. "
                "run `tripwire auth login` again to request a fresh code."
            ) from exc
        raise


def _credentials_from_login(
    server: str, response: dict[str, Any], email: str | None = None
) -> credentials.Credentials:
    # Validate the required fields rather than caching a broken, unusable token.
    user_id = response.get("user_id")
    access_token = response.get("access_token")
    try:
        expires_at = int(response["expires_at"])
    except (KeyError, TypeError, ValueError):
        expires_at = None  # type: ignore[assignment]
    if not user_id or not access_token or expires_at is None:
        raise click.ClickException(
            "the login response was malformed (missing "
            "user_id/access_token/expires_at); run `tripwire auth login` again."
        )
    # Store the server only when it is a non-default (self-hosted / test) target,
    # so a normal user's cache omits it.
    return credentials.Credentials(
        server=None if server == DEFAULT_SERVER else server,
        user_id=user_id,
        access_token=access_token,
        expires_at=expires_at,
        email=email,
    )


@auth.command("logout")
@click.pass_obj
@_handle_errors
def auth_logout(obj: Context) -> None:
    """Forget the cached token."""
    _out("cached token removed" if obj.store.clear() else "no cached token")


@auth.command("status")
@click.pass_obj
@_handle_errors
def auth_status(obj: Context) -> None:
    """Show who you are logged in as, and when the session expires."""
    creds = obj.current_credentials()
    if creds is None:
        raise click.ClickException("not logged in. run `tripwire auth login`.")
    _out(_identity_line(creds))
    if creds.is_expired():
        _out("session: expired. run `tripwire auth login`")
    else:
        expiry = time.strftime("%Y-%m-%d %H:%M", time.gmtime(creds.expires_at))
        _out(f"session: valid until {expiry} UTC")


# The pre-0.4 spellings. Registered (hidden) only so they fail with a migration
# hint instead of click's bare "No such command". Not aliases: they do not log
# anyone in.
@cli.command("login", hidden=True, context_settings={"ignore_unknown_options": True})
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def moved_login(args: tuple[str, ...]) -> None:
    raise click.ClickException("`tripwire login` moved to `tripwire auth login`")


@cli.command("logout", hidden=True, context_settings={"ignore_unknown_options": True})
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def moved_logout(args: tuple[str, ...]) -> None:
    raise click.ClickException("`tripwire logout` moved to `tripwire auth logout`")


@cli.command()
@click.option("--watch", is_flag=True, help="re-poll and redraw every few seconds")
@click.option("--json", "as_json", is_flag=True, help="emit verbatim server JSON")
@click.pass_obj
@_handle_errors
def status(obj: Context, watch: bool, as_json: bool) -> None:
    """Cross-object dashboard: identity, counts, fired-first canaries."""
    if watch and as_json:
        # Watch is a live human view; JSON is a one-shot machine read.
        _err("note: --watch is ignored with --json.")
        watch = False
    if not watch:
        _render_status_once(obj, as_json)
        return
    # Resolve auth once up front (signing in first if needed), then poll every 5s,
    # clearing the screen between frames, until interrupted. A transient error
    # between frames is tolerated: warn and keep polling rather than exiting.
    obj.require_credentials()
    while True:
        click.echo("\x1b[2J\x1b[H", nl=False)
        try:
            _render_status_once(obj, False)
        except (click.Abort, click.ClickException, KeyboardInterrupt):
            # A cancelled sign-in, or a refusal to sign in at all, is the user's
            # decision -- not a blip to ride out. `click.Abort` subclasses
            # RuntimeError, so without this the bare `except Exception` below
            # would eat the Ctrl+C and re-prompt every five seconds forever.
            raise
        except Exception as exc:  # noqa: BLE001 - keep polling across transients
            _err(f"(temporary error: {exc}; retrying in 5s...)")
        time.sleep(5)


def _render_status_once(obj: Context, as_json: bool) -> None:
    creds = obj.require_credentials()
    response = obj.authed_client().list_canaries()
    if as_json:
        _print_json(response)
        return
    canaries = response.get("canaries") or []
    fired = [c for c in canaries if _has_fired(c)]
    rest = [c for c in canaries if not _has_fired(c)]

    _out(_identity_line(creds))
    _out()
    _out(f"{len(canaries)} canaries, {len(fired)} fired")

    if not canaries:
        _out()
        _out("no canaries yet. create one with `tripwire canary create <type>`.")
        return
    if fired:
        _out()
        _out("FIRED")
        for canary in fired:
            _out(_canary_row(canary))
    if rest:
        _out()
        _out("ARMED")
        for canary in rest:
            _out(_canary_row(canary))


# --- canary group -----------------------------------------------------------


@cli.group()
def canary() -> None:
    """Create and manage canaries."""


@canary.command(
    "create",
    help=(
        "Create a canary; the credential is shown once, at creation.\n\n"
        "TYPE is one of: " + ", ".join(CREATABLE_TYPES) + "."
    ),
)
@click.argument("canary_type", metavar="TYPE", required=False)
@click.option("--note", help="your own note to remember where you placed it")
@click.option(
    "-o", "--output", "output",
    help="write the credential to a file instead of stdout",
)
@click.pass_obj
@_handle_errors
def canary_create(
    obj: Context, canary_type: str | None, note: str | None, output: str | None
) -> None:
    if not canary_type:
        raise click.ClickException(
            "a canary type is required. run `tripwire canary create --help` for the list."
        )
    placement = resolve_placement(canary_type)
    if placement is not None:
        _run_placement_create(obj, placement, note, output)
        return
    _run_type_create(obj, resolve_type(canary_type), note, output)


def _run_type_create(
    obj: Context, entry: TypeEntry, note: str | None, output: str | None
) -> None:
    """Ordinary create: mint the canary and print only its credential fields."""
    payload: dict[str, Any] = {"type": entry.wire}
    if note:
        payload["memo"] = note
    result = _create_or_explain(obj, payload, entry.wait_seconds)
    if output:
        _write_json_reveal(result, output)
        return
    for name in entry.output_fields:
        value = result.get(name)
        if value is not None and value != "":
            _out(f"{name}: {value}")


def _run_placement_create(
    obj: Context, placement: PlacementDef, note: str | None, output: str | None
) -> None:
    """Placement create: mint the underlying canary and render it into a block."""
    entry = resolve_type(placement.underlying_type)
    payload: dict[str, Any] = {"type": entry.wire}
    if note:
        payload["memo"] = note
    result = _create_or_explain(obj, payload, entry.wait_seconds)

    access_key_id = _str(result.get("access_key_id"))
    secret = _str(result.get("secret_access_key"))
    region = _str(result.get("region"))
    if not access_key_id or not secret:
        # Safety valve: the canary was minted but we cannot render the block.
        # Never drop the one-time secret -- dump the raw response, then error.
        _err("!! could not render the block; the canary was minted, raw response below.")
        click.echo(json.dumps(result, indent=2))
        raise click.ClickException(
            "could not render the placement block; the raw response was printed above."
        )

    # The profile/label name is generated by the backend and returned as `name`.
    name = _str(result.get("name")) or _str(result.get("id"))
    block = placement.render(name, access_key_id, secret, region)
    label = block.split("\n", 1)[0]

    if output:
        _deliver_to_file(block, output, label)
    else:
        _deliver_to_stdout(block)


def _create_or_explain(
    obj: Context, payload: dict[str, Any], wait_seconds: float
) -> dict[str, Any]:
    """Run POST /canary, translating the create-specific failures (a still-
    provisioning orphan; a hard provisioning failure) into actionable messages."""
    try:
        return obj.authed_client().create_canary(payload, timeout=wait_seconds)
    except ApiError as exc:
        message = _create_error_message(exc)
        if message is None:
            raise
        raise click.ClickException(message) from exc


def _create_error_message(exc: ApiError) -> str | None:
    """Friendly text for the create-specific failures, or ``None`` to fall back
    to the generic error handler."""
    if exc.status == 429 and exc.detail == "canary_pending":
        return (
            "the canary is still being prepared, so its one-time credential was "
            "not returned. creating again would make a second one; instead find "
            "it with `tripwire canary list`, delete it with `tripwire canary "
            "delete <id>`, then retry."
        )
    if exc.status == 502 and exc.detail == "provisioning_failed":
        return "the canary could not be created; nothing was issued. please try again."
    return None


def _deliver_to_stdout(block: str) -> None:
    """Print the block to stdout with a leading + trailing newline, so `>>`/`>`
    compose cleanly and never fuse a header."""
    click.echo("\n" + block)


def _deliver_to_file(block: str, output_path: str, label: str) -> None:
    """Write the block to ``output_path`` (append-or-create, mode 0600), or fall
    back to stdout with a loud warning if the write fails after the credential
    was already minted."""
    try:
        mode0600 = _write_block(output_path, block)
    except OSError as exc:
        _err("")
        _err(f"!! could not write to {output_path}: {exc}")
        _err("!! the credential was already minted and is shown below - capture it now,")
        _err("!! it will NOT be shown again.")
        _deliver_to_stdout(block)
        return
    if mode0600:
        _err(f"wrote {label} to {output_path} (mode 0600)")
    else:
        _err(
            f"wrote {label} to {output_path}, but could not set mode 0600; "
            f"tighten it yourself: chmod 600 {output_path}"
        )


def _write_block(path: str, block: str) -> bool:
    """Write ``block`` (no trailing newline) to ``path`` -- create with parent
    dirs, or append with a blank-line separator so blocks never fuse -- then
    tighten to mode 0600. Returns whether the chmod succeeded."""
    p = Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"{block}\n")
    else:
        non_empty = p.stat().st_size > 0
        with p.open("a") as handle:
            handle.write(f"\n{block}\n" if non_empty else f"{block}\n")
    try:
        p.chmod(0o600)
        return True
    except OSError:
        return False


def _write_json_reveal(result: dict[str, Any], output_path: str) -> None:
    """Write the full create JSON to ``output_path`` (mode 0600). If the write
    fails, dump the JSON to stdout with a warning (post-mint safety valve); if
    only the chmod fails, warn about perms without re-dumping the secret."""
    text = json.dumps(result, indent=2) + "\n"
    try:
        with open(output_path, "w") as handle:
            handle.write(text)
    except OSError as exc:
        _err(f"!! could not write to {output_path}: {exc}; the credential is below.")
        click.echo(text, nl=False)
        return
    try:
        os.chmod(output_path, 0o600)
        _err(f"wrote {output_path}")
    except OSError as exc:
        _err(
            f"wrote {output_path}, but could not set mode 0600 ({exc}); "
            f"run: chmod 600 {output_path}"
        )


@canary.command("list")
@click.option("--type", "type_filter", help="filter by type")
@click.option("--fired", is_flag=True, help="only canaries that have fired")
@click.option("--json", "as_json", is_flag=True, help="emit verbatim server JSON")
@click.pass_obj
@_handle_errors
def canary_list(
    obj: Context, type_filter: str | None, fired: bool, as_json: bool
) -> None:
    """List your canaries."""
    response = obj.authed_client().list_canaries()
    canaries = response.get("canaries") or []
    if type_filter:
        wire = resolve_type(type_filter).wire
        canaries = [c for c in canaries if c.get("type") == wire]
    if fired:
        canaries = [c for c in canaries if _has_fired(c)]
    if as_json:
        # Verbatim server truth (filtered), snake types preserved for scripts.
        _print_json({"canaries": canaries})
        return
    if not canaries:
        _out("no canaries match.")
        return
    for canary_summary in canaries:
        _out(_canary_row(canary_summary).lstrip())


@canary.command("show")
@click.argument("canary_id")
@click.option("--json", "as_json", is_flag=True, help="emit verbatim server JSON")
@click.pass_obj
@_handle_errors
def canary_show(obj: Context, canary_id: str, as_json: bool) -> None:
    """Show one canary, including fire hits."""
    canary_summary = obj.authed_client().get_canary(canary_id)
    if as_json:
        _print_json(canary_summary)
        return
    _out(_canary_row(canary_summary).lstrip())
    if _has_fired(canary_summary):
        _out(f"fired: last used {canary_summary.get('last_used_at')}")
    else:
        _out("fired: no hits yet")
    _out(f"actions: tripwire canary delete {canary_id}")


@canary.command("delete")
@click.argument("canary_id")
@click.pass_obj
@_handle_errors
def canary_delete(obj: Context, canary_id: str) -> None:
    """Delete a canary."""
    _print_json(obj.authed_client().delete_canary(canary_id))


# --- bundle group (public endpoints, but the CLI still requires login) ------


@cli.group()
def bundle() -> None:
    """Download bait bundles."""


# Backoff schedule (seconds) between download retries while a bundle is preparing.
_RETRY_BACKOFF = [0.75, 1.5, 2.5]


def download_with_retry(
    client: ApiClient,
    bundle_id: str,
    *,
    attempts: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[Any, bytes]:
    """Download a bundle, retrying while the server reports
    ``409 bundle_preparing``. Any other error propagates immediately. On
    exhausted retries the last 409 propagates (mapped to a clear message)."""
    if attempts is None:
        attempts = len(_RETRY_BACKOFF) + 1
    last_error: ApiError | None = None
    for attempt in range(attempts):
        try:
            return client.download_bundle(bundle_id)
        except ApiError as exc:
            preparing = exc.status == 409 and exc.detail == "bundle_preparing"
            if not preparing:
                raise
            last_error = exc
            if attempt < attempts - 1:
                sleep(_RETRY_BACKOFF[min(attempt, len(_RETRY_BACKOFF) - 1)])
    raise last_error if last_error is not None else ApiError(409, "bundle_preparing")


def _decode_uri_component(value: str) -> str:
    """Mirror JS ``decodeURIComponent``: raise on an invalid ``%XX`` or on
    invalid UTF-8, so a malformed ``filename*`` falls through to the plain form."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("invalid percent-encoding")
    return urllib.parse.unquote(value, errors="strict")


def _sanitize_filename(name: str) -> str:
    return os.path.basename(name.replace("\\", "/"))


def filename_from_disposition(value: str | None) -> str | None:
    """Parse the download filename from a ``Content-Disposition`` header,
    preferring the RFC 5987 ``filename*`` form. Returns the basename only (no
    path parts), or ``None`` if none is present."""
    if not value:
        return None
    extended = re.search(r"filename\*=(?:UTF-8'')?[\"']?([^\"';]+)", value, re.I)
    if extended:
        try:
            return _sanitize_filename(_decode_uri_component(extended.group(1).strip()))
        except (ValueError, UnicodeDecodeError):
            # Malformed percent-encoding: fall through to the plain form, and
            # ultimately to the caller's `${bundle_id}.zip` default.
            pass
    plain = re.search(r"filename=\"?([^\"';]+)\"?", value, re.I)
    if plain:
        return _sanitize_filename(plain.group(1).strip())
    return None


def _is_unsafe_entry(name: str, root: str) -> bool:
    """True when a zip entry is absolute or escapes ``root`` via ``..``."""
    if name.startswith("/") or os.path.isabs(name):
        return True
    target = os.path.realpath(os.path.join(root, name))
    return not (target == root or target.startswith(root + os.sep))


def extract_zip(buffer: bytes, directory: str) -> tuple[int, list[str]]:
    """Extract a zip ``buffer`` into ``directory``, guarding against zip-slip:
    any entry that is absolute or resolves outside the dir (``..``) is SKIPPED,
    not written, even though the archive comes from our own server. Intermediate
    dirs are created (0700); files are written 0600. Returns the count written
    and the names skipped."""
    root = os.path.realpath(directory)
    skipped: list[str] = []
    written = 0
    with zipfile.ZipFile(io.BytesIO(buffer)) as archive:
        for info in archive.infolist():
            raw_name = info.filename
            name = raw_name.replace("\\", "/")
            if name.endswith("/"):
                continue  # directory entry -- created implicitly below
            if _is_unsafe_entry(name, root):
                skipped.append(raw_name)
                continue
            target = os.path.realpath(os.path.join(root, name))
            # The extracted files hold planted credentials: dirs 0700, files 0600.
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(archive.read(info))
            os.chmod(target, 0o600)
            written += 1
    return written, skipped


def _display_path(path: str) -> str:
    """A path for display: bare names get a `./` prefix to read as a local path."""
    if path.startswith(("/", ".", "~")):
        return path
    return f"./{path}"


def _human_bytes(count: int) -> str:
    if count < 1000:
        return f"{count} B"
    if count < 1_000_000:
        return f"{count / 1000:.1f} kB"
    return f"{count / 1_000_000:.1f} MB"


def _bundle_error_message(exc: ApiError) -> str | None:
    """Friendly text for the shared bundle error responses, or ``None`` to fall
    through to the generic error handler."""
    if exc.status == 404:
        return "bundle not found; check the id."
    if exc.status == 410:
        return f"bundle is {exc.detail} and can no longer be accessed."
    if exc.status == 409 and exc.detail == "bundle_preparing":
        return "the bundle is still being prepared; try again shortly."
    if exc.status == 429:
        return "rate limited; wait a few minutes and try again."
    if exc.status == 400 and exc.detail == "challenge_failed":
        return (
            "bundle creation requires browser verification; download it from "
            "https://tripwire.so."
        )
    return None


@bundle.command("download")
@click.argument("bundle_id", metavar="[ID]", required=False)
@click.option(
    "-o", "--output", "output",
    help="extract dir (default ./<name>/); with --zip, the .zip file; "
    "'-' streams the zip to stdout",
)
@click.option(
    "--zip", "keep_zip", is_flag=True,
    help="keep the raw .zip archive instead of extracting it",
)
@click.pass_obj
@_handle_errors
def bundle_download(
    obj: Context, bundle_id: str | None, output: str | None, keep_zip: bool
) -> None:
    """Download a bundle and extract it; with no id, issue a fresh bundle for you first."""
    # Login guard: resolve the authed client first, which signs the user in (or,
    # without a TTY, fails fast) BEFORE any request is made.
    client = obj.authed_client()
    try:
        _run_bundle_download(client, bundle_id, output, keep_zip)
    except ApiError as exc:
        message = _bundle_error_message(exc)
        if message is None:
            raise
        raise click.ClickException(message) from exc


def _run_bundle_download(
    client: ApiClient, bundle_id: str | None, output: str | None, keep_zip: bool
) -> None:
    # No id given: issue a fresh bundle for the logged-in user first, then
    # download it. The create body is empty -- the auth-derived recipient and the
    # template are both chosen server-side (no email / turnstile_token / template).
    if not bundle_id:
        created = client.create_bundle({})
        bundle_id = created.get("bundle_id")
        if not bundle_id:
            raise click.ClickException(
                "bundle creation did not return an id; nothing to download."
            )
        _err(f"created bundle {bundle_id} for you; downloading...")

    headers, buffer = download_with_retry(client, bundle_id)
    filename = filename_from_disposition(headers.get("content-disposition")) or f"{bundle_id}.zip"
    # `<name>` = the filename without its `.zip` suffix (fallback: bundle id).
    name = re.sub(r"\.zip$", "", filename, flags=re.I) or bundle_id

    # `-o -` streams the raw zip bytes to stdout (for piping), taking precedence.
    if output == "-":
        click.get_binary_stream("stdout").write(buffer)
        _err(f"wrote {len(buffer)} bytes to stdout")
        return

    # `--zip` keeps the raw archive instead of extracting.
    if keep_zip:
        if output:
            dest = os.path.join(output, filename) if os.path.isdir(output) else output
        else:
            dest = filename
        # Refuse to clobber an existing archive (matches the extract path's
        # non-empty-dir guard).
        if os.path.exists(dest):
            raise click.ClickException(
                f"{_display_path(dest)} already exists; remove it or pass a "
                "different -o path."
            )
        with open(dest, "wb") as handle:
            handle.write(buffer)
        os.chmod(dest, 0o600)
        _err(f"saved {filename} ({_human_bytes(len(buffer))}) -> {_display_path(dest)}")
        return

    # DEFAULT: extract into `./<name>/` (or `-o <dir>`).
    directory = output or name
    if os.path.exists(directory):
        if not os.path.isdir(directory):
            raise click.ClickException(
                f"{_display_path(directory)} exists and is not a directory; "
                "pass -o <dir> or use --zip."
            )
        if os.listdir(directory):
            raise click.ClickException(
                f"target directory {_display_path(directory)} already exists and "
                "is not empty; remove it or pass -o <empty-dir> (or use --zip to "
                "keep the archive)."
            )
    os.makedirs(directory, mode=0o700, exist_ok=True)  # holds planted credentials
    written, skipped = extract_zip(buffer, directory)
    for bad in skipped:
        _err(f"skipped unsafe zip entry: {bad}")
    _err(f"extracted {written} files -> {_display_path(directory)}/")


def _str(value: Any) -> str:
    return "" if value is None else str(value)


def main() -> None:
    cli(prog_name="tripwire")


if __name__ == "__main__":
    main()
