"""Command-line client for Tripwire canaries.

Commands:
  tripwire login                       log in (email-code by default), cache a
                                       token; --user-id/--password for operators
  tripwire logout                      forget the cached token
  tripwire whoami                      print the cached identity
  tripwire canaries list               list your canaries (summary only)
  tripwire canaries get <id>           show one canary summary
  tripwire canaries create --type ...  create a canary; its credential is
                                       returned once, in this response
  tripwire canaries deactivate <id>    deactivate a canary
  tripwire canaries delete <id>        delete a canary

`login` does not take a server flag. The server is resolved as
$TRIPWIRE_SERVER, then the last-used cached server, then the default; set
$TRIPWIRE_SERVER to point at a self-hosted or test server.
"""

from __future__ import annotations

import functools
import json
import os
import subprocess
from collections.abc import Callable
from typing import Any

import click

from tripwire_cli import credentials
from tripwire_cli.client import CREATE_READ_TIMEOUT, ApiClient, ApiError


def _git_user_email() -> str | None:
    """Best-effort default email from ``git config user.email``; ``None`` if
    git is absent or unset. Shown to the user as a default, never used
    silently."""
    try:
        result = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    email = result.stdout.strip()
    return email or None

DEFAULT_SERVER = "https://tripwire.so/api/v1"

# The canary types the API's POST /canary accepts. The provider-minted types
# (aws/anthropic/github) take ~2 min to provision; the request-path types
# (web_login_credential, browser_session_cookie, postgres_login,
# kubernetes_kubeconfig) inline their artifact fields directly in the create
# response. The CLI prints the server JSON verbatim, so new inlined fields flow
# through unchanged.
CANARY_TYPES = [
    "dns_label",
    "aws_access_key",
    "anthropic_api_key",
    "github_pat",
    "web_login_credential",
    "browser_session_cookie",
    "postgres_login",
    "kubernetes_kubeconfig",
]

# How long the create read timeout may run, in seconds. Must stay above the
# server's synchronous create wait window (180s) so the client never abandons a
# request whose one-time credential reveal the server is still preparing.
CREATE_TIMEOUT_ENV = "TRIPWIRE_CREATE_TIMEOUT"

# How many times to re-prompt for the emailed code before giving up. Re-prompts
# never re-call /auth/login/start (which is rate-limited); they re-submit a new
# code against the same challenge.
EMAIL_CODE_ATTEMPTS = 3


def resolve_login_server(env: dict[str, str], cached: str | None) -> str:
    """Server URL for `login`: env override, else the last-used cached server,
    else the default."""
    return env.get("TRIPWIRE_SERVER") or cached or DEFAULT_SERVER


def build_create_payload(*, canary_type: str, memo: str | None = None) -> dict[str, Any]:
    """Build the create request body from the supported flags."""
    payload: dict[str, Any] = {"type": canary_type}
    if memo:
        payload["memo"] = memo
    return payload


class Context:
    """Shared state for the commands: the credential store and a factory that
    builds an :class:`ApiClient` from a server URL and optional token. Both are
    injectable so tests can supply fakes."""

    def __init__(
        self,
        store: credentials.CredentialStore | None = None,
        client_factory: Callable[[str, str | None], ApiClient] | None = None,
        git_email: Callable[[], str | None] | None = None,
    ):
        self.store = store or credentials.default_store()
        self._client_factory = client_factory or (
            lambda server, token=None: ApiClient(base_url=server, token=token)
        )
        # Injectable so tests can supply a fake; defaults to `git config
        # user.email`.
        self._git_email = git_email or _git_user_email

    def git_email(self) -> str | None:
        return self._git_email()

    def client(self, server: str, token: str | None = None) -> ApiClient:
        return self._client_factory(server, token)

    def authed_client(self) -> ApiClient:
        creds = self.store.load()
        return self.client(creds.server, creds.access_token)

    def cached_server(self) -> str | None:
        try:
            return self.store.load().server
        except credentials.NoCredentialsError:
            return None


# Substrings the server (or its JWT/Fernet token layer) leaks on a 401 when the
# cached token is malformed or undecodable. These are opaque to users, so we map
# them to a plain "session expired" message instead of echoing the raw detail.
_EXPIRED_SESSION_TOKEN_MARKERS = (
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
    if any(marker in lowered for marker in _EXPIRED_SESSION_TOKEN_MARKERS):
        return "session expired; run `tripwire login`"
    return f"401: {detail}\nhint: run `tripwire login`"


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


def _echo_json(value: Any) -> None:
    click.echo(json.dumps(value, indent=2))


@click.group()
@click.version_option(package_name="tripwire-cli", prog_name="tripwire")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Tripwire canary client."""
    ctx.obj = ctx.obj or Context()


@cli.command()
@click.option("--user-id", help="operator user id (selects password login)")
@click.option(
    "--password", help="operator password (selects password login; prefer the prompt)"
)
@click.option(
    "--email",
    help="email for passwordless login (skips the prompt; for headless/CI use)",
)
@click.option(
    "--code",
    help=(
        "6-digit code for passwordless login (skips the code prompt; pair with "
        "--email for a non-interactive exchange of an already-sent code)"
    ),
)
@click.pass_obj
@_handle_errors
def login(
    obj: Context,
    user_id: str | None,
    password: str | None,
    email: str | None,
    code: str | None,
) -> None:
    """Log in and cache a token.

    Defaults to passwordless email-code login. Passing --user-id or --password
    selects the operator (user-id + password) login instead, so operator
    scripts keep working unchanged.

    For headless/CI use, pass --email (and optionally --code) to skip the
    interactive prompts. With both --email and --code, a code that was already
    emailed is exchanged directly without re-sending one or prompting.
    """
    server = resolve_login_server(dict(os.environ), obj.cached_server())
    client = obj.client(server)
    if user_id is not None or password is not None:
        creds = _password_login(client, server, user_id, password)
    else:
        creds = _email_login(client, server, obj.git_email(), email=email, code=code)
    path = obj.store.save(creds)
    click.echo(f"logged in as {creds.user_id} ({creds.role}); token cached at {path}")


def _password_login(
    client: ApiClient, server: str, user_id: str | None, password: str | None
) -> credentials.Credentials:
    """Operator login: user-id + password."""
    user_id = user_id or click.prompt("user_id")
    password = password or click.prompt("password", hide_input=True)
    response = client.login(user_id, password)
    return _credentials_from_login(server, response)


def _email_login(
    client: ApiClient,
    server: str,
    default_email: str | None,
    *,
    email: str | None = None,
    code: str | None = None,
) -> credentials.Credentials:
    """Passwordless email-code login.

    Interactive path (no ``code``): calls /auth/login/start once (it is
    rate-limited), then prompts for the 6-digit code, re-prompting in-band on an
    invalid/expired code without re-calling start.

    Non-interactive path (``code`` supplied): exchanges that code directly and
    does NOT call /auth/login/start, since the code was already emailed and
    re-sending would burn the rate-limited start and invalidate the held code.

    ``email`` (e.g. from ``--email``) skips the email prompt for headless/CI use.
    """
    email = email or click.prompt("email", default=default_email)

    if code is not None:
        # Headless: a code was supplied, so do not (re)send one. Exchange it
        # directly; a single attempt, no prompt loop.
        response = _exchange_code(client, email, code)
        return _credentials_from_login(server, response, email=email)

    _start_email_login(client, email)
    click.echo(f"sent a 6-digit sign-in code to {email}; check your inbox.")
    last_error: ApiError | None = None
    for attempt in range(EMAIL_CODE_ATTEMPTS):
        entered = click.prompt("code")
        try:
            response = _exchange_code(client, email, entered)
        except ApiError as exc:
            if exc.status == 400 and exc.detail == "invalid_or_expired_code":
                last_error = exc
                remaining = EMAIL_CODE_ATTEMPTS - attempt - 1
                if remaining:
                    click.echo(
                        f"invalid or expired code; {remaining} attempt(s) left.",
                        err=True,
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
                "try `tripwire login` again."
            ) from exc
        raise


def _exchange_code(client: ApiClient, email: str, code: str) -> dict[str, Any]:
    """Exchange a code for a token. A server-side 5xx here is the dangerous case:
    the code may already have been consumed, so retrying the same code is futile
    and silently re-sending one would burn the rate-limited start. Surface a
    clear message and have the user re-run `tripwire login` for a fresh code."""
    try:
        return client.login_with_code(email, code)
    except ApiError as exc:
        if exc.status >= 500:
            raise click.ClickException(
                "the server errored while verifying your code "
                f"({exc.status}: {exc.detail}); your code may already be spent. "
                "run `tripwire login` again to request a fresh code."
            ) from exc
        raise


def _credentials_from_login(
    server: str, response: dict[str, Any], email: str | None = None
) -> credentials.Credentials:
    return credentials.Credentials(
        server=server,
        user_id=response["user_id"],
        access_token=response["access_token"],
        expires_at=int(response["expires_at"]),
        role=response["role"],
        email=email,
    )


@cli.command()
@click.pass_obj
@_handle_errors
def logout(obj: Context) -> None:
    """Forget the cached token."""
    click.echo("cached token removed" if obj.store.clear() else "no cached token")


@cli.command()
@click.pass_obj
@_handle_errors
def whoami(obj: Context) -> None:
    """Print the cached identity."""
    creds = obj.store.load()
    click.echo(f"server:   {creds.server}")
    click.echo(f"user_id:  {creds.user_id}")
    if creds.email:
        click.echo(f"email:    {creds.email}")
    click.echo(f"role:     {creds.role}")


@cli.group()
def canaries() -> None:
    """Manage canaries."""


@canaries.command("list")
@click.pass_obj
@_handle_errors
def canaries_list(obj: Context) -> None:
    """List the canaries you own (summary only)."""
    _echo_json(obj.authed_client().list_canaries())


@canaries.command("get")
@click.argument("canary_id")
@click.pass_obj
@_handle_errors
def canaries_get(obj: Context, canary_id: str) -> None:
    """Show one canary summary (no credential)."""
    _echo_json(obj.authed_client().get_canary(canary_id))


@canaries.command("create")
@click.option(
    "--type", "canary_type", type=click.Choice(CANARY_TYPES), required=True
)
@click.option("--memo", help="free-form note about this canary")
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=None,
    help=(
        "read timeout in seconds for this create "
        f"(env {CREATE_TIMEOUT_ENV}; default 240). Must exceed the server's "
        "~180s provisioning wait."
    ),
)
@click.pass_obj
@_handle_errors
def canaries_create(
    obj: Context, canary_type: str, memo: str | None, timeout: float | None
) -> None:
    """Create a canary. The credential is returned once, in this response."""
    read_timeout = _resolve_create_timeout(timeout, dict(os.environ))
    payload = build_create_payload(canary_type=canary_type, memo=memo)
    click.echo(
        "creating the canary (usually a second or two; up to ~2 min if the "
        "warm pool is cold).",
        err=True,
    )
    try:
        result = obj.authed_client().create_canary(payload, timeout=read_timeout)
    except ApiError as exc:
        message = _create_error_message(exc)
        if message is None:
            raise
        raise click.ClickException(message) from exc
    _echo_json(result)


def _resolve_create_timeout(flag: float | None, env: dict[str, str]) -> float:
    """Read timeout for create, in seconds: --timeout flag, else
    ``TRIPWIRE_CREATE_TIMEOUT`` env, else ``CREATE_READ_TIMEOUT`` (240). Always
    above the server's ~180s provisioning wait so the client never abandons a
    create whose one-time reveal is still being prepared."""
    if flag is not None:
        return flag
    raw = env.get(CREATE_TIMEOUT_ENV)
    if not raw:
        return CREATE_READ_TIMEOUT
    try:
        return float(raw)
    except ValueError as exc:
        raise click.ClickException(
            f"invalid {CREATE_TIMEOUT_ENV}={raw!r}: must be a number of seconds"
        ) from exc


def _create_error_message(exc: ApiError) -> str | None:
    """Friendly text for the create-specific failures, or ``None`` to fall back
    to the generic error handler."""
    if exc.status == 429 and exc.detail == "canary_pending":
        return (
            "canary is still provisioning, so its one-time credential reveal was "
            "not returned in this response and cannot be recovered. creating "
            "again would mint a second canary and trip the per-type quota; "
            "instead, find this orphan with `tripwire canaries list`, delete it "
            "with `tripwire canaries delete <id>`, then recreate."
        )
    if exc.status == 502 and exc.detail == "provisioning_failed":
        return (
            "canary provisioning failed; nothing was issued. "
            "try again, and if it persists contact support."
        )
    return None


@canaries.command("deactivate")
@click.argument("canary_id")
@click.pass_obj
@_handle_errors
def canaries_deactivate(obj: Context, canary_id: str) -> None:
    """Deactivate a canary."""
    _echo_json(obj.authed_client().deactivate_canary(canary_id))


@canaries.command("delete")
@click.argument("canary_id")
@click.pass_obj
@_handle_errors
def canaries_delete(obj: Context, canary_id: str) -> None:
    """Delete a canary."""
    _echo_json(obj.authed_client().delete_canary(canary_id))


def main() -> None:
    cli(prog_name="tripwire")


if __name__ == "__main__":
    main()
