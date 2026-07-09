from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from tripwire_cli import credentials
from tripwire_cli.cli import (
    CANARY_TYPES,
    DEFAULT_SERVER,
    Context,
    build_create_payload,
    cli,
    resolve_login_server,
    _unauthorized_message,
)
from tripwire_cli.client import ApiError

# Known one-time output fields. None of these should appear in a get/list
# summary fixture.
_CREDENTIAL_FIELDS = {
    "access_key_id",
    "secret_access_key",
    "region",
    "raw_token",
    "raw_key",
    "fqdn",
    "qtype",
    "url",
    "username",
    "password",
    "cookie_name",
    "cookie_value",
    "cookie_domain",
    "cookie_path",
    "database_url",
    "host",
    "port",
    "database",
    "sslmode",
    "server",
    "cluster_name",
    "user_name",
    "bearer_token",
    "token",
    "kubeconfig",
}


class _FakeClient:
    """Stand-in for ApiClient: returns a canned result or raises a canned error,
    and records the calls it received."""

    def __init__(self, *, result=None, error: ApiError | None = None):
        self._result = result
        self._error = error
        self.created_payloads: list[dict] = []
        self.create_timeouts: list[float | None] = []
        self.login_starts: list[str] = []
        self.code_logins: list[tuple[str, str]] = []

    def _answer(self):
        if self._error is not None:
            raise self._error
        return self._result

    def login_start(self, email):
        self.login_starts.append(email)
        return {"status": "ok"}

    def login_with_code(self, email, code):
        self.code_logins.append((email, code))
        return self._answer()

    def create_canary(self, payload, timeout=None):
        self.created_payloads.append(payload)
        self.create_timeouts.append(timeout)
        return self._answer()

    def get_canary(self, canary_id):
        return self._answer()

    def list_canaries(self):
        return self._answer()

    def deactivate_canary(self, canary_id):
        return self._answer()

    def delete_canary(self, canary_id):
        return self._answer()


class _CodeSequenceClient(_FakeClient):
    """Email-code login fake: `login_with_code` raises an invalid-code error
    for the first ``invalid_attempts`` calls, then returns ``result``. Lets a
    test drive the CLI's bounded re-prompt loop without re-calling start."""

    def __init__(self, *, result, invalid_attempts: int):
        super().__init__(result=result)
        self._invalid_attempts = invalid_attempts

    def login_with_code(self, email, code):
        self.code_logins.append((email, code))
        if len(self.code_logins) <= self._invalid_attempts:
            raise ApiError(400, "invalid_or_expired_code")
        return self._result


def _context(tmp_path, client: _FakeClient) -> Context:
    store = credentials.CredentialStore(tmp_path / "credentials.json")
    return Context(store=store, client_factory=lambda server, token=None: client)


def _logged_in_context(tmp_path, client: _FakeClient) -> Context:
    ctx = _context(tmp_path, client)
    ctx.store.save(
        credentials.Credentials(
            server="https://api.example",
            user_id="usr_alice",
            access_token="tok",
            expires_at=1700000000,
        )
    )
    return ctx


def _summary(**overrides) -> dict:
    summary = {
        "id": "can_1",
        "type": "aws_access_key",
        "status": "active",
        "user_id": "usr_alice",
        "memo": None,
        "expires_at": None,
        "last_checked_at": "2026-06-01T00:00:00Z",
        "last_used_at": None,
        "created_at": "2026-06-01T00:00:00Z",
        "updated_at": "2026-06-01T00:00:00Z",
    }
    summary.update(overrides)
    return summary


# --- pure helpers -----------------------------------------------------------


def test_resolve_login_server_precedence():
    assert (
        resolve_login_server({"TRIPWIRE_SERVER": "https://env.example"}, "https://cached")
        == "https://env.example"
    )
    assert resolve_login_server({}, "https://cached.example") == "https://cached.example"
    assert resolve_login_server({}, None) == DEFAULT_SERVER
    assert DEFAULT_SERVER == "https://tripwire.so/api/v1"


def test_build_create_payload_matches_api_contract():
    assert build_create_payload(canary_type="aws_access_key") == {"type": "aws_access_key"}
    assert build_create_payload(canary_type="github_pat", memo="ci runner") == {
        "type": "github_pat",
        "memo": "ci runner",
    }
    assert build_create_payload(canary_type="postgres_login") == {"type": "postgres_login"}


def test_canary_types_are_the_customer_types():
    # Provider types not released in the CLI and `dns_label` remain available
    # to the API but are deliberately excluded from the public CLI surface.
    assert CANARY_TYPES == [
        "aws_access_key",
        "web_login_credential",
        "browser_session_cookie",
        "postgres_login",
        "kubernetes_kubeconfig",
    ]
    assert "dns_label" not in CANARY_TYPES


@pytest.mark.parametrize(
    "path",
    [Path(__file__).parents[1] / "README.md"],
)
def test_readme_lists_every_supported_create_type(path: Path):
    text = path.read_text(encoding="utf-8")

    assert all(canary_type in text for canary_type in CANARY_TYPES)


@pytest.mark.parametrize(
    "canary_type",
    [
        "web_login_credential",
        "browser_session_cookie",
        "postgres_login",
        "kubernetes_kubeconfig",
    ],
)
def test_create_accepts_request_path_types(tmp_path, canary_type: str):
    # The four request-path types are now part of the public --type surface and
    # send the same {"type": ...} body as the provider types.
    canary = {"id": "can_1", "type": canary_type, "status": "active"}
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", canary_type],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.output
    assert client.created_payloads == [{"type": canary_type}]


@pytest.mark.parametrize(
    "canary_type,inlined",
    [
        (
            "web_login_credential",
            {
                "url": "https://app.example/login",
                "username": "svc-backups",
                "password": "s3kret",
            },
        ),
        (
            "browser_session_cookie",
            {
                "url": "https://app.example",
                "cookie_name": "session",
                "cookie_value": "abc.def",
                "cookie_domain": "app.example",
                "cookie_path": "/",
            },
        ),
        (
            "postgres_login",
            {
                "database_url": "postgres://u:p@h:5432/db?sslmode=require",
                "host": "h",
                "port": 5432,
                "database": "db",
                "username": "u",
                "password": "p",
                "sslmode": "require",
                "url": "postgres://h:5432",
            },
        ),
        (
            "kubernetes_kubeconfig",
            {
                "kubeconfig": "apiVersion: v1\nkind: Config\n",
                "server": "https://k8s.example:6443",
                "cluster_name": "prod",
                "user_name": "deployer",
                "bearer_token": "eyJ.tok",
                "token": "eyJ.tok",
            },
        ),
    ],
)
def test_create_prints_request_path_inlined_fields_verbatim(
    tmp_path, canary_type: str, inlined: dict
):
    # The create response inlines each type's artifact fields; the CLI prints
    # the server JSON unchanged and must not filter any field out.
    canary = {"id": "can_1", "type": canary_type, "status": "active", **inlined}
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", canary_type],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == canary


# --- argument surface -------------------------------------------------------


def test_login_has_no_server_flag():
    runner = CliRunner()
    rejected = runner.invoke(cli, ["login", "--server", "https://x"])
    assert rejected.exit_code != 0
    assert "no such option" in rejected.output.lower()


def test_create_rejects_unknown_type():
    runner = CliRunner()
    result = runner.invoke(cli, ["canaries", "create", "--type", "nope"])
    assert result.exit_code != 0


def test_create_rejects_dns_label(tmp_path):
    # dns_label is internal and not part of the CLI --type choices.
    client = _FakeClient(result={"id": "can_1"})
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "dns_label"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    assert client.created_payloads == []


def test_create_requires_type():
    runner = CliRunner()
    result = runner.invoke(cli, ["canaries", "create"])
    assert result.exit_code != 0


# --- create -----------------------------------------------------------------


def test_create_prints_inlined_canary_verbatim(tmp_path):
    canary = {
        "id": "can_1",
        "type": "aws_access_key",
        "status": "active",
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "sekret",
        "region": "us-east-1",
    }
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0
    # The progress note goes to stderr; stdout stays clean JSON.
    assert json.loads(result.stdout) == canary
    assert client.created_payloads == [{"type": "aws_access_key"}]


def test_create_emits_provisioning_progress_message(tmp_path):
    canary = {"id": "can_1", "type": "aws_access_key", "status": "active"}
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0
    # The "still working" note goes to stderr so stdout stays clean JSON.
    assert "creating the canary" in result.stderr
    assert "2 min" in result.stderr
    assert json.loads(result.stdout) == canary


def test_create_passes_default_long_read_timeout(tmp_path):
    canary = {"id": "can_1", "type": "aws_access_key", "status": "active"}
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0
    # Default create read timeout must exceed the server wait window (180s).
    assert client.create_timeouts == [240.0]


def test_create_timeout_flag_overrides_default(tmp_path):
    canary = {"id": "can_1", "type": "aws_access_key", "status": "active"}
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key", "--timeout", "300"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0
    assert client.create_timeouts == [300.0]


def test_create_timeout_env_overrides_default(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_CREATE_TIMEOUT", "420")
    canary = {"id": "can_1", "type": "aws_access_key", "status": "active"}
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0
    assert client.create_timeouts == [420.0]


def test_create_timeout_flag_beats_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_CREATE_TIMEOUT", "420")
    canary = {"id": "can_1", "type": "aws_access_key", "status": "active"}
    client = _FakeClient(result=canary)
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key", "--timeout", "300"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0
    assert client.create_timeouts == [300.0]


def test_create_surfaces_canary_pending_message(tmp_path):
    client = _FakeClient(error=ApiError(429, "canary_pending"))
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    # Pending means the one-time reveal is gone; the fix is delete + recreate,
    # NOT retry (a retry mints a second canary and trips the cap-1 quota).
    assert "delete" in result.output
    assert "recreate" in result.output
    assert "one-time" in result.output
    assert "quota" in result.output
    # Must not tell the user to retry the create.
    assert "retry the create" not in result.output


def test_create_surfaces_provisioning_failed_message(tmp_path):
    client = _FakeClient(error=ApiError(502, "provisioning_failed"))
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    assert "provisioning failed" in result.output


def test_create_reports_unrelated_api_errors_generically(tmp_path):
    client = _FakeClient(error=ApiError(403, "quota_exceeded"))
    result = CliRunner().invoke(
        cli,
        ["canaries", "create", "--type", "aws_access_key"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    assert "403: quota_exceeded" in result.output


# --- summaries --------------------------------------------------------------


def test_get_prints_summary_without_credential(tmp_path):
    summary = _summary()
    client = _FakeClient(result=summary)
    result = CliRunner().invoke(
        cli, ["canaries", "get", "can_1"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    out = json.loads(result.output)
    assert out == summary
    assert _CREDENTIAL_FIELDS.isdisjoint(out)


def test_list_prints_summaries_without_credential(tmp_path):
    listing = {
        "canaries": [
            _summary(id="can_1", type="aws_access_key"),
            _summary(id="can_2", type="github_pat"),
        ]
    }
    client = _FakeClient(result=listing)
    result = CliRunner().invoke(
        cli, ["canaries", "list"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    out = json.loads(result.output)
    assert out == listing
    for entry in out["canaries"]:
        assert _CREDENTIAL_FIELDS.isdisjoint(entry)


# --- auth-required commands -------------------------------------------------


def test_commands_need_login(tmp_path):
    client = _FakeClient(result={"canaries": []})
    # Context with an empty store: no cached credentials.
    result = CliRunner().invoke(
        cli, ["canaries", "list"], obj=_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "not logged in" in result.output


# --- login / logout / whoami ------------------------------------------------


# Login is email-code only: the password and non-interactive --code login paths
# were removed, so those flags no longer exist.


@pytest.mark.parametrize("flag", ["--user-id", "--password", "--code"])
def test_login_rejects_removed_flags(flag):
    result = CliRunner().invoke(cli, ["login", flag, "x"])
    assert result.exit_code != 0
    assert "no such option" in result.output.lower()


def test_login_emails_a_code_and_caches_it(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _FakeClient(
        result={
            "user_id": "usr_alice",
            "access_token": "tok",
            "expires_at": 1700000000,
            "role": "user",
        }
    )
    ctx = _context(tmp_path, client)
    # Input: email, then the 6-digit code.
    result = CliRunner().invoke(
        cli, ["login"], input="alice@example.com\n123456\n", obj=ctx
    )
    assert result.exit_code == 0, result.output
    assert client.login_starts == ["alice@example.com"]
    assert client.code_logins == [("alice@example.com", "123456")]
    loaded = ctx.store.load()
    assert loaded.access_token == "tok"
    assert loaded.email == "alice@example.com"
    assert loaded.server == "https://api.example"


def test_login_against_default_server_omits_server_and_role(tmp_path, monkeypatch):
    # Logging into the public default writes no `server` field, and the login
    # response's `role` is never persisted.
    monkeypatch.delenv("TRIPWIRE_SERVER", raising=False)
    client = _FakeClient(
        result={
            "user_id": "usr_alice",
            "access_token": "tok",
            "expires_at": 1700000000,
            "role": "user",
        }
    )
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(
        cli, ["login"], input="alice@example.com\n123456\n", obj=ctx
    )
    assert result.exit_code == 0, result.output
    on_disk = json.loads((tmp_path / "credentials.json").read_text())
    assert "server" not in on_disk
    assert "role" not in on_disk
    loaded = ctx.store.load()
    assert loaded.server is None
    assert loaded.resolved_server() == DEFAULT_SERVER


def test_login_email_default_comes_from_git_config(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _FakeClient(
        result={
            "user_id": "usr_alice",
            "access_token": "tok",
            "expires_at": 1700000000,
            "role": "user",
        }
    )
    ctx = _context(tmp_path, client)
    ctx._git_email = lambda: "git@example.com"
    # Accept the shown default by pressing enter, then supply the code.
    result = CliRunner().invoke(cli, ["login"], input="\n123456\n", obj=ctx)
    assert result.exit_code == 0, result.output
    # The default is shown, not silently used.
    assert "git@example.com" in result.output
    assert client.login_starts == ["git@example.com"]
    assert client.code_logins == [("git@example.com", "123456")]


def test_login_email_reprompts_on_invalid_code_without_recalling_start(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _CodeSequenceClient(
        result={
            "user_id": "usr_alice",
            "access_token": "tok",
            "expires_at": 1700000000,
            "role": "user",
        },
        invalid_attempts=2,
    )
    ctx = _context(tmp_path, client)
    # email, then two bad codes, then a good one.
    result = CliRunner().invoke(
        cli,
        ["login"],
        input="alice@example.com\n000000\n111111\n123456\n",
        obj=ctx,
    )
    assert result.exit_code == 0, result.output
    # start() is rate-limited, so it must be called exactly once.
    assert client.login_starts == ["alice@example.com"]
    assert client.code_logins == [
        ("alice@example.com", "000000"),
        ("alice@example.com", "111111"),
        ("alice@example.com", "123456"),
    ]
    assert ctx.store.load().access_token == "tok"


def test_login_email_gives_up_after_too_many_bad_codes(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _CodeSequenceClient(
        result={
            "user_id": "usr_alice",
            "access_token": "tok",
            "expires_at": 1700000000,
            "role": "user",
        },
        invalid_attempts=99,
    )
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(
        cli,
        ["login"],
        input="alice@example.com\n000000\n111111\n222222\n",
        obj=ctx,
    )
    assert result.exit_code != 0
    # start() called once; code attempts bounded (~3) without re-calling start.
    assert client.login_starts == ["alice@example.com"]
    assert len(client.code_logins) == 3
    assert "invalid_or_expired_code" in result.output


def test_logout_reports_state(tmp_path):
    client = _FakeClient()
    ctx = _logged_in_context(tmp_path, client)
    first = CliRunner().invoke(cli, ["logout"], obj=ctx)
    assert "cached token removed" in first.output
    second = CliRunner().invoke(cli, ["logout"], obj=_context(tmp_path, client))
    assert "no cached token" in second.output


def test_whoami_prints_identity(tmp_path):
    client = _FakeClient()
    result = CliRunner().invoke(cli, ["whoami"], obj=_logged_in_context(tmp_path, client))
    assert result.exit_code == 0
    assert "usr_alice" in result.output
    assert "https://api.example" in result.output


def test_whoami_prints_email_when_present(tmp_path):
    client = _FakeClient()
    ctx = _context(tmp_path, client)
    ctx.store.save(
        credentials.Credentials(
            server="https://api.example",
            user_id="usr_alice",
            access_token="tok",
            expires_at=1700000000,
            email="alice@example.com",
        )
    )
    result = CliRunner().invoke(cli, ["whoami"], obj=ctx)
    assert result.exit_code == 0
    assert "alice@example.com" in result.output


# --- login: --email flag ----------------------------------------------------


class _StartErrorClient(_FakeClient):
    """Email-login fake whose /auth/login/start raises a canned ApiError, so a
    test can drive the rate-limit (429) path."""

    def __init__(self, *, start_error: ApiError):
        super().__init__(result=None)
        self._start_error = start_error

    def login_start(self, email):
        self.login_starts.append(email)
        raise self._start_error


class _CodeErrorClient(_FakeClient):
    """Email-login fake whose /auth/login (code exchange) raises a canned
    ApiError, so a test can drive the server-error (5xx) path. start() succeeds
    so the test reaches the exchange."""

    def __init__(self, *, code_error: ApiError):
        super().__init__(result=None)
        self._code_error = code_error

    def login_with_code(self, email, code):
        self.code_logins.append((email, code))
        raise self._code_error


_GOOD_LOGIN = {
    "user_id": "usr_alice",
    "access_token": "tok",
    "expires_at": 1700000000,
    "role": "user",
}


def test_login_email_flag_skips_email_prompt_only(tmp_path, monkeypatch):
    # --email without --code: start is sent (no code yet) and only the code is
    # prompted for.
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _FakeClient(result=_GOOD_LOGIN)
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(
        cli, ["login", "--email", "ci@example.com"], input="123456\n", obj=ctx
    )
    assert result.exit_code == 0, result.output
    assert client.login_starts == ["ci@example.com"]
    assert client.code_logins == [("ci@example.com", "123456")]


# --- login resilience: start rate limit (429) -------------------------------


def test_login_start_rate_limit_gives_friendly_message(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _StartErrorClient(start_error=ApiError(429, "rate_limited"))
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(cli, ["login"], input="alice@example.com\n", obj=ctx)
    assert result.exit_code != 0
    # Friendly, actionable text rather than a raw "429: rate_limited".
    assert "too many login attempts from this network" in result.output
    assert "~10 minutes" in result.output
    assert "429: rate_limited" not in result.output
    # No token cached on a failed login.
    assert not (tmp_path / "credentials.json").exists()


def test_login_start_non_429_error_is_not_masked(tmp_path, monkeypatch):
    # A non-rate-limit start failure keeps the generic API-error surface.
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _StartErrorClient(start_error=ApiError(503, "upstream_down"))
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(cli, ["login"], input="alice@example.com\n", obj=ctx)
    assert result.exit_code != 0
    assert "503: upstream_down" in result.output


# --- login resilience: 5xx on the code exchange -----------------------------


@pytest.mark.parametrize("status", [500, 502, 503])
def test_login_code_exchange_5xx_tells_user_code_may_be_spent(
    tmp_path, monkeypatch, status
):
    # A 5xx during the code exchange may have consumed the code server-side;
    # retrying the same code is futile, so the CLI exits cleanly and tells the
    # user to re-run login for a fresh code.
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _CodeErrorClient(code_error=ApiError(status, "internal_error"))
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(
        cli, ["login"], input="alice@example.com\n123456\n", obj=ctx
    )
    assert result.exit_code != 0
    # start() was called exactly once; the code was attempted exactly once (no
    # silent retry of a possibly-spent code).
    assert client.login_starts == ["alice@example.com"]
    assert client.code_logins == [("alice@example.com", "123456")]
    assert "may already be spent" in result.output
    assert "run `tripwire login` again" in result.output
    assert not (tmp_path / "credentials.json").exists()


# --- login resilience: 401 detail polish ------------------------------------


@pytest.mark.parametrize(
    "raw_detail",
    [
        "Invalid header padding",
        "Invalid token",
        "Not enough segments",
        "Signature verification failed",
        "token expired",
        "Failed to decrypt token",
    ],
)
def test_unauthorized_message_maps_token_errors_to_session_expired(raw_detail):
    assert _unauthorized_message(raw_detail) == "session expired; run `tripwire login`"


def test_unauthorized_message_keeps_meaningful_detail():
    assert _unauthorized_message("forbidden_scope") == (
        "401: forbidden_scope\nhint: run `tripwire login`"
    )


def test_list_maps_opaque_401_to_session_expired(tmp_path):
    # A 401 whose detail is a raw token-decode error becomes a clean
    # session-expired prompt instead of leaking "Invalid header padding".
    client = _FakeClient(error=ApiError(401, "Invalid header padding"))
    result = CliRunner().invoke(
        cli, ["canaries", "list"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "session expired; run `tripwire login`" in result.output
    assert "Invalid header padding" not in result.output
