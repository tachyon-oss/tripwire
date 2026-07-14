from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from tripwire_cli import credentials
from tripwire_cli.cli import (
    CREATABLE_TYPES,
    DEFAULT_SERVER,
    Context,
    UnknownTypeError,
    _armed_word,
    _canary_row,
    _has_fired,
    _identity_line,
    cli,
    dotted_for_wire,
    download_with_retry,
    extract_zip,
    filename_from_disposition,
    render_aws_credentials,
    render_aws_profile,
    resolve_login_server,
    resolve_placement,
    resolve_type,
    _unauthorized_message,
)
from tripwire_cli.client import ApiError

# Known one-time credential fields; none should leak into a summary row.
_CREDENTIAL_FIELDS = {
    "access_key_id",
    "secret_access_key",
    "raw_token",
    "raw_key",
    "cookie_value",
    "bearer_token",
    "kubeconfig",
    "database_url",
    "password",
}


def _make_zip(files: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


FIXTURE_ZIP = _make_zip({"README.md": "hello\n", "src/app.py": "print(1)\n"})


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

    def delete_canary(self, canary_id):
        return self._answer()


class _CodeSequenceClient(_FakeClient):
    """Email-code login fake: `login_with_code` raises an invalid-code error for
    the first ``invalid_attempts`` calls, then returns ``result``."""

    def __init__(self, *, result, invalid_attempts: int):
        super().__init__(result=result)
        self._invalid_attempts = invalid_attempts

    def login_with_code(self, email, code):
        self.code_logins.append((email, code))
        if len(self.code_logins) <= self._invalid_attempts:
            raise ApiError(400, "invalid_or_expired_code")
        return self._result


class _BundleClient:
    """Routes the two bundle POSTs and records every call. `create_bundle`
    returns a fresh id; `download_bundle` returns (headers, zip bytes) or raises
    a canned error (optionally only for the first ``fail_times`` downloads)."""

    def __init__(
        self,
        *,
        create_id="b_auto",
        disposition='attachment; filename="ledgerflow.zip"',
        zip_bytes=FIXTURE_ZIP,
        create_error: ApiError | None = None,
        download_error: ApiError | None = None,
        fail_times: int | None = None,
    ):
        self.calls: list[tuple[str, str, dict | None]] = []
        self._create_id = create_id
        self._disposition = disposition
        self._zip_bytes = zip_bytes
        self._create_error = create_error
        self._download_error = download_error
        self._fail_times = fail_times
        self._downloads = 0

    def create_bundle(self, body):
        self.calls.append(("POST", "/bundles", body))
        if self._create_error is not None:
            raise self._create_error
        return {"status": "ready", "bundle_id": self._create_id}

    def download_bundle(self, bundle_id):
        self.calls.append(("POST", f"/bundles/{bundle_id}", None))
        self._downloads += 1
        if self._download_error is not None:
            if self._fail_times is None or self._downloads <= self._fail_times:
                raise self._download_error
        return ({"content-disposition": self._disposition}, self._zip_bytes)


def _context(tmp_path, client) -> Context:
    store = credentials.CredentialStore(tmp_path / "credentials.json")
    return Context(store=store, client_factory=lambda server, token=None: client)


# A cached session must be UNEXPIRED, or an authenticated command would try to
# sign the user in again instead of using it.
VALID_UNTIL = 4_102_444_800  # 2100-01-01Z, epoch seconds


def _logged_in_context(tmp_path, client, *, email=None) -> Context:
    ctx = _context(tmp_path, client)
    ctx.store.save(
        credentials.Credentials(
            server="https://api.example",
            user_id="usr_alice",
            access_token="tok",
            expires_at=VALID_UNTIL,
            email=email,
        )
    )
    return ctx


def _summary(**overrides) -> dict:
    summary = {
        "id": "can_1",
        "type": "aws_access_key",
        "status": "active",
        "memo": None,
        "last_used_at": None,
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


def test_creatable_types_are_dotted_customer_ids_plus_placements():
    assert CREATABLE_TYPES == [
        "aws.access_key",
        "github.token",
        "database.credentials",
        "web.login",
        "web.cookie",
        "k8s.config",
        "aws.profile",
        "aws.credentials",
    ]
    # Unreleased/internal types are not creatable.
    assert "anthropic.api_key" not in CREATABLE_TYPES
    assert "dns.label" not in CREATABLE_TYPES


def test_resolve_type_maps_dotted_to_wire():
    assert resolve_type("aws.access_key").wire == "aws_access_key"
    assert resolve_type("k8s.config").wire == "kubernetes_kubeconfig"
    # Case-insensitive, trimmed.
    assert resolve_type("  Web.Login  ").wire == "web_login_credential"


@pytest.mark.parametrize("given", ["nope", "aws_access_key", "dns.label", "anthropic.api_key"])
def test_resolve_type_rejects_non_customer_or_snake_input(given):
    with pytest.raises(UnknownTypeError):
        resolve_type(given)


def test_dotted_for_wire_round_trips_and_falls_back():
    assert dotted_for_wire("aws_access_key") == "aws.access_key"
    assert dotted_for_wire("github_pat") == "github.token"
    assert dotted_for_wire("mystery") == "mystery"


def test_resolve_placement():
    assert resolve_placement("aws.profile").underlying_type == "aws.access_key"
    assert resolve_placement("aws.credentials").underlying_type == "aws.access_key"
    assert resolve_placement("aws.access_key") is None


def test_placement_renderers():
    profile = render_aws_profile("warehouse", "AKIA1", "sekret", "us-east-1")
    assert profile.splitlines() == [
        "[profile warehouse]",
        "aws_access_key_id = AKIA1",
        "aws_secret_access_key = sekret",
        "region = us-east-1",
    ]
    # No region line when region is empty.
    assert "region" not in render_aws_profile("w", "AKIA1", "sekret", "")
    creds = render_aws_credentials("warehouse", "AKIA1", "sekret", "us-east-1")
    assert creds.splitlines() == [
        "[warehouse]",
        "aws_access_key_id = AKIA1",
        "aws_secret_access_key = sekret",
    ]


def test_format_helpers():
    assert _has_fired(_summary(last_used_at="2026-06-01T00:00:00Z")) is True
    assert _has_fired(_summary()) is False
    assert _armed_word("active") == "armed"
    assert _armed_word("inactive") == "disarmed"
    assert _armed_word(None) == "unknown"
    row = _canary_row(_summary(id="can_9", type="github_pat", memo="ci"))
    assert row == "  can_9  github.token  armed  ci"
    fired_row = _canary_row(_summary(last_used_at="2026-06-01T00:00:00Z"))
    assert "used 2026-06-01T00:00:00Z" in fired_row


def test_identity_line_hides_default_server_shows_email():
    creds = credentials.Credentials(
        user_id="usr_alice", access_token="t", expires_at=1, email="a@b.com"
    )
    # No server (default) -> not shown; email shown.
    assert _identity_line(creds) == "usr_alice  a@b.com"
    creds2 = credentials.Credentials(
        server="https://self.host", user_id="usr_alice", access_token="t", expires_at=1
    )
    assert _identity_line(creds2) == "usr_alice  https://self.host"


# --- login / logout ---------------------------------------------------------


def test_login_has_no_server_flag():
    rejected = CliRunner().invoke(cli, ["auth", "login", "--server", "https://x"])
    assert rejected.exit_code != 0
    assert "no such option" in rejected.output.lower()


@pytest.mark.parametrize("flag", ["--user-id", "--password", "--code"])
def test_login_rejects_removed_flags(flag):
    result = CliRunner().invoke(cli, ["auth", "login", flag, "x"])
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
    result = CliRunner().invoke(cli, ["auth", "login"], input="alice@example.com\n123456\n", obj=ctx)
    assert result.exit_code == 0, result.output
    assert client.login_starts == ["alice@example.com"]
    assert client.code_logins == [("alice@example.com", "123456")]
    loaded = ctx.store.load()
    assert loaded.access_token == "tok"
    assert loaded.email == "alice@example.com"
    assert loaded.server == "https://api.example"
    assert "logged in as usr_alice" in result.output


def test_login_against_default_server_omits_server_and_role(tmp_path, monkeypatch):
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
    result = CliRunner().invoke(cli, ["auth", "login"], input="alice@example.com\n123456\n", obj=ctx)
    assert result.exit_code == 0, result.output
    on_disk = json.loads((tmp_path / "credentials.json").read_text())
    assert "server" not in on_disk
    assert "role" not in on_disk
    loaded = ctx.store.load()
    assert loaded.server is None
    assert loaded.resolved_server() == DEFAULT_SERVER


def test_login_email_default_comes_from_cached_login(tmp_path, monkeypatch):
    # The prompt default is the email from a prior login (the cache), NOT git.
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _FakeClient(
        result={"user_id": "usr_alice", "access_token": "tok", "expires_at": 1700000000}
    )
    ctx = _logged_in_context(tmp_path, client, email="prior@example.com")
    result = CliRunner().invoke(cli, ["auth", "login"], input="\n123456\n", obj=ctx)
    assert result.exit_code == 0, result.output
    assert "prior@example.com" in result.output
    assert client.login_starts == ["prior@example.com"]


def test_login_email_reprompts_on_invalid_code_without_recalling_start(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _CodeSequenceClient(
        result={"user_id": "usr_alice", "access_token": "tok", "expires_at": 1700000000},
        invalid_attempts=2,
    )
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(
        cli, ["auth", "login"], input="alice@example.com\n000000\n111111\n123456\n", obj=ctx
    )
    assert result.exit_code == 0, result.output
    assert client.login_starts == ["alice@example.com"]
    assert client.code_logins == [
        ("alice@example.com", "000000"),
        ("alice@example.com", "111111"),
        ("alice@example.com", "123456"),
    ]


def test_login_email_gives_up_after_too_many_bad_codes(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _CodeSequenceClient(
        result={"user_id": "usr_alice", "access_token": "tok", "expires_at": 1700000000},
        invalid_attempts=99,
    )
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(
        cli, ["auth", "login"], input="alice@example.com\n000000\n111111\n222222\n", obj=ctx
    )
    assert result.exit_code != 0
    assert client.login_starts == ["alice@example.com"]
    assert len(client.code_logins) == 3
    assert "invalid_or_expired_code" in result.output


def test_login_email_flag_skips_email_prompt_only(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")
    client = _FakeClient(
        result={"user_id": "usr_alice", "access_token": "tok", "expires_at": 1700000000}
    )
    ctx = _context(tmp_path, client)
    result = CliRunner().invoke(
        cli, ["auth", "login", "--email", "ci@example.com"], input="123456\n", obj=ctx
    )
    assert result.exit_code == 0, result.output
    assert client.login_starts == ["ci@example.com"]
    assert client.code_logins == [("ci@example.com", "123456")]


def test_login_start_rate_limit_gives_friendly_message(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")

    class _StartErr(_FakeClient):
        def login_start(self, email):
            self.login_starts.append(email)
            raise ApiError(429, "rate_limited")

    ctx = _context(tmp_path, _StartErr())
    result = CliRunner().invoke(cli, ["auth", "login"], input="alice@example.com\n", obj=ctx)
    assert result.exit_code != 0
    assert "too many login attempts from this network" in result.output
    assert "429: rate_limited" not in result.output
    assert not (tmp_path / "credentials.json").exists()


@pytest.mark.parametrize("status", [500, 502, 503])
def test_login_code_exchange_5xx_tells_user_code_may_be_spent(tmp_path, monkeypatch, status):
    monkeypatch.setenv("TRIPWIRE_SERVER", "https://api.example")

    class _CodeErr(_FakeClient):
        def login_with_code(self, email, code):
            self.code_logins.append((email, code))
            raise ApiError(status, "internal_error")

    ctx = _context(tmp_path, _CodeErr())
    result = CliRunner().invoke(cli, ["auth", "login"], input="alice@example.com\n123456\n", obj=ctx)
    assert result.exit_code != 0
    assert "may already be spent" in result.output
    assert not (tmp_path / "credentials.json").exists()


def test_logout_reports_state(tmp_path):
    client = _FakeClient()
    ctx = _logged_in_context(tmp_path, client)
    first = CliRunner().invoke(cli, ["auth", "logout"], obj=ctx)
    assert "cached token removed" in first.output
    second = CliRunner().invoke(cli, ["auth", "logout"], obj=_context(tmp_path, client))
    assert "no cached token" in second.output


# --- removed commands are gone ----------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["whoami"],
        ["api", "GET", "/x"],
        ["canary", "disarm", "can_1"],
        ["canary", "deactivate", "can_1"],
        ["canary", "get", "can_1"],
        ["canary", "types"],
        ["canaries", "list"],
        ["bundle", "show", "b1"],
        ["bundle", "contents", "b1"],
        ["bundle", "create"],
    ],
)
def test_removed_commands_are_not_registered(argv):
    result = CliRunner().invoke(cli, argv)
    assert result.exit_code != 0
    assert "no such command" in result.output.lower() or "usage" in result.output.lower()


def test_create_rejects_expires_option(tmp_path):
    client = _FakeClient(result=_summary())
    result = CliRunner().invoke(
        cli,
        ["canary", "create", "aws.access_key", "--expires", "30d"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    assert "no such option" in result.output.lower()


# --- canary create ----------------------------------------------------------


def test_create_prints_only_credential_fields(tmp_path):
    result_obj = {
        "id": "can_1",
        "type": "aws_access_key",
        "status": "active",
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "sekret",
        "region": "us-east-1",
    }
    client = _FakeClient(result=result_obj)
    result = CliRunner().invoke(
        cli, ["canary", "create", "aws.access_key"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.stderr
    assert result.stdout.splitlines() == [
        "access_key_id: AKIAIOSFODNN7EXAMPLE",
        "secret_access_key: sekret",
        "region: us-east-1",
    ]
    # No progress note, and the wire type is snake.
    assert "creating" not in result.stderr.lower()
    assert client.created_payloads == [{"type": "aws_access_key"}]
    assert client.create_timeouts == [240.0]


def test_create_sends_note_as_memo(tmp_path):
    client = _FakeClient(result=_summary(raw_token="ghp_x"))
    result = CliRunner().invoke(
        cli,
        ["canary", "create", "github.token", "--note", "ci runner"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.output
    assert client.created_payloads == [{"type": "github_pat", "memo": "ci runner"}]


def test_create_output_writes_json_file_mode_600(tmp_path):
    result_obj = {"id": "can_1", "type": "aws_access_key", "access_key_id": "AKIA", "secret_access_key": "s"}
    client = _FakeClient(result=result_obj)
    out_file = tmp_path / "cred.json"
    result = CliRunner().invoke(
        cli,
        ["canary", "create", "aws.access_key", "-o", str(out_file)],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.stderr
    assert json.loads(out_file.read_text()) == result_obj
    assert result.stdout == ""  # secret went to the file, not stdout
    assert oct(out_file.stat().st_mode & 0o777) == "0o600"
    assert f"wrote {out_file}" in result.stderr


@pytest.mark.parametrize(
    "placement,first_line",
    [("aws.profile", "[profile warehouse-key]"), ("aws.credentials", "[warehouse-key]")],
)
def test_create_placement_renders_block_with_backend_name(tmp_path, placement, first_line):
    # The profile/label name comes from the backend `name`, and the underlying
    # canary is the aws_access_key type.
    result_obj = {
        "id": "can_1",
        "name": "warehouse-key",
        "access_key_id": "AKIAEXAMPLE",
        "secret_access_key": "sekret",
        "region": "us-east-1",
    }
    client = _FakeClient(result=result_obj)
    result = CliRunner().invoke(
        cli, ["canary", "create", placement], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.stderr
    assert client.created_payloads == [{"type": "aws_access_key"}]
    lines = result.stdout.splitlines()
    assert lines[0] == ""  # leading blank line (compose-clean contract)
    assert lines[1] == first_line
    assert "aws_access_key_id = AKIAEXAMPLE" in result.stdout


def test_create_placement_name_falls_back_to_id(tmp_path):
    result_obj = {"id": "can_xyz", "access_key_id": "AKIA", "secret_access_key": "s"}
    client = _FakeClient(result=result_obj)
    result = CliRunner().invoke(
        cli, ["canary", "create", "aws.credentials"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.stderr
    assert "[can_xyz]" in result.stdout


def test_create_user_cannot_pass_a_name(tmp_path):
    client = _FakeClient(result=_summary())
    result = CliRunner().invoke(
        cli,
        ["canary", "create", "aws.profile", "--name", "chosen"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    assert "no such option" in result.output.lower()


def test_create_requires_type(tmp_path):
    client = _FakeClient(result=_summary())
    result = CliRunner().invoke(
        cli, ["canary", "create"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "a canary type is required" in result.output


def test_create_rejects_unknown_type(tmp_path):
    client = _FakeClient(result=_summary())
    result = CliRunner().invoke(
        cli, ["canary", "create", "nope"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "unknown canary type" in result.output
    assert client.created_payloads == []


def test_create_surfaces_canary_pending_message(tmp_path):
    client = _FakeClient(error=ApiError(429, "canary_pending"))
    result = CliRunner().invoke(
        cli, ["canary", "create", "aws.access_key"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "delete" in result.output
    assert "retry" in result.output


def test_create_surfaces_provisioning_failed_message(tmp_path):
    client = _FakeClient(error=ApiError(502, "provisioning_failed"))
    result = CliRunner().invoke(
        cli, ["canary", "create", "aws.access_key"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "could not be created" in result.output


def test_create_reports_unrelated_api_errors_generically(tmp_path):
    client = _FakeClient(error=ApiError(403, "quota_exceeded"))
    result = CliRunner().invoke(
        cli, ["canary", "create", "aws.access_key"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "403: quota_exceeded" in result.output


# --- canary list / show / delete --------------------------------------------


def test_list_renders_rows_by_default(tmp_path):
    listing = {
        "canaries": [
            _summary(id="can_1", type="aws_access_key"),
            _summary(id="can_2", type="github_pat", last_used_at="2026-06-02T00:00:00Z"),
        ]
    }
    client = _FakeClient(result=listing)
    result = CliRunner().invoke(
        cli, ["canary", "list"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines[0] == "can_1  aws.access_key  armed"
    assert lines[1].startswith("can_2  github.token  used 2026-06-02")
    for line in lines:
        for field in _CREDENTIAL_FIELDS:
            assert field not in line


def test_list_json_is_verbatim_filtered(tmp_path):
    listing = {
        "canaries": [
            _summary(id="can_1", type="aws_access_key"),
            _summary(id="can_2", type="github_pat"),
        ]
    }
    client = _FakeClient(result=listing)
    result = CliRunner().invoke(
        cli, ["canary", "list", "--type", "github.token", "--json"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.output
    out = json.loads(result.output)
    assert [c["id"] for c in out["canaries"]] == ["can_2"]


def test_list_fired_filter(tmp_path):
    listing = {
        "canaries": [
            _summary(id="can_1"),
            _summary(id="can_2", last_used_at="2026-06-02T00:00:00Z"),
        ]
    }
    client = _FakeClient(result=listing)
    result = CliRunner().invoke(
        cli, ["canary", "list", "--fired"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.output
    assert "can_2" in result.output
    assert "can_1" not in result.output


def test_list_empty_message(tmp_path):
    client = _FakeClient(result={"canaries": []})
    result = CliRunner().invoke(
        cli, ["canary", "list"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    assert "no canaries match." in result.output


def test_show_renders_row_and_fire_state(tmp_path):
    client = _FakeClient(result=_summary(id="can_1", last_used_at="2026-06-02T00:00:00Z"))
    result = CliRunner().invoke(
        cli, ["canary", "show", "can_1"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.output
    assert "fired: last used 2026-06-02T00:00:00Z" in result.output
    assert "actions: tripwire canary delete can_1" in result.output


def test_show_no_hits_yet(tmp_path):
    client = _FakeClient(result=_summary(id="can_1"))
    result = CliRunner().invoke(
        cli, ["canary", "show", "can_1"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    assert "fired: no hits yet" in result.output


def test_show_json(tmp_path):
    summary = _summary(id="can_1")
    client = _FakeClient(result=summary)
    result = CliRunner().invoke(
        cli, ["canary", "show", "can_1", "--json"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == summary


def test_delete_prints_json(tmp_path):
    client = _FakeClient(result={"id": "can_1", "status": "deleted"})
    result = CliRunner().invoke(
        cli, ["canary", "delete", "can_1"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == {"id": "can_1", "status": "deleted"}


# --- status -----------------------------------------------------------------


def test_status_dashboard_fired_first(tmp_path):
    listing = {
        "canaries": [
            _summary(id="can_armed"),
            _summary(id="can_fired", last_used_at="2026-06-02T00:00:00Z"),
        ]
    }
    client = _FakeClient(result=listing)
    result = CliRunner().invoke(
        cli, ["status"], obj=_logged_in_context(tmp_path, client, email="a@b.com")
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "usr_alice  a@b.com  https://api.example" in out
    assert "2 canaries, 1 fired" in out
    assert out.index("FIRED") < out.index("ARMED")
    assert out.index("can_fired") < out.index("can_armed")


def test_status_empty(tmp_path):
    client = _FakeClient(result={"canaries": []})
    result = CliRunner().invoke(
        cli, ["status"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    assert "0 canaries, 0 fired" in result.output
    assert "no canaries yet" in result.output


def test_status_json(tmp_path):
    listing = {"canaries": [_summary(id="can_1")]}
    client = _FakeClient(result=listing)
    result = CliRunner().invoke(
        cli, ["status", "--json"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == listing


# --- auth-required + 401 -----------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [["canary", "list"], ["canary", "show", "can_1"], ["status"], ["bundle", "download"]],
)
def test_commands_need_login(tmp_path, argv):
    client = _FakeClient(result={"canaries": []})
    result = CliRunner().invoke(cli, argv, obj=_context(tmp_path, client))
    assert result.exit_code != 0
    assert "not logged in" in result.output


@pytest.mark.parametrize(
    "raw_detail",
    ["Invalid header padding", "Invalid token", "token expired", "Failed to decrypt token"],
)
def test_unauthorized_message_maps_token_errors_to_session_expired(raw_detail):
    assert _unauthorized_message(raw_detail) == "session expired; run `tripwire auth login`"


def test_unauthorized_message_keeps_meaningful_detail():
    assert _unauthorized_message("forbidden_scope") == (
        "401: forbidden_scope\nhint: run `tripwire auth login`"
    )


def test_list_maps_opaque_401_to_session_expired(tmp_path):
    client = _FakeClient(error=ApiError(401, "Invalid header padding"))
    result = CliRunner().invoke(
        cli, ["canary", "list"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "session expired; run `tripwire auth login`" in result.output
    assert "Invalid header padding" not in result.output


# --- bundle download helpers ------------------------------------------------


@pytest.mark.parametrize(
    "header,expected",
    [
        ('attachment; filename="bundle.zip"', "bundle.zip"),
        ("attachment; filename=ledgerflow.zip", "ledgerflow.zip"),
        ("attachment; filename=\"a.zip\"; filename*=UTF-8''b%20c.zip", "b c.zip"),
        ('attachment; filename="../../etc/passwd"', "passwd"),
        (None, None),
        ("inline", None),
        # Malformed filename* falls through to the plain filename.
        ("attachment; filename=\"ok.zip\"; filename*=UTF-8''%ZZ", "ok.zip"),
    ],
)
def test_filename_from_disposition(header, expected):
    assert filename_from_disposition(header) == expected


def test_extract_zip_safe(tmp_path):
    target = tmp_path / "out"
    written, skipped = extract_zip(FIXTURE_ZIP, str(target))
    assert written == 2
    assert skipped == []
    assert (target / "README.md").read_text() == "hello\n"
    assert (target / "src" / "app.py").read_text() == "print(1)\n"
    assert oct((target / "README.md").stat().st_mode & 0o777) == "0o600"


def test_extract_zip_skips_traversal(tmp_path):
    evil = _make_zip({"safe.txt": "ok", "../evil.txt": "pwned"})
    target = tmp_path / "out"
    target.mkdir()
    written, skipped = extract_zip(evil, str(target))
    assert (target / "safe.txt").read_text() == "ok"
    assert not (tmp_path / "evil.txt").exists()
    assert "../evil.txt" in skipped
    assert written == 1


def test_download_with_retry_retries_then_succeeds():
    client = _BundleClient(
        download_error=ApiError(409, "bundle_preparing"), fail_times=2
    )
    slept: list[float] = []
    headers, buffer = download_with_retry(
        client, "b1", sleep=lambda s: slept.append(s)
    )
    assert buffer == FIXTURE_ZIP
    assert len(slept) == 2  # two backoffs before the third attempt succeeds


def test_download_with_retry_propagates_non_409():
    client = _BundleClient(download_error=ApiError(404, "bundle_not_found"))
    with pytest.raises(ApiError) as exc:
        download_with_retry(client, "b1", sleep=lambda s: None)
    assert exc.value.status == 404


# --- bundle download command ------------------------------------------------


def test_bundle_download_no_id_creates_then_extracts(tmp_path):
    client = _BundleClient(create_id="b_auto")
    target = tmp_path / "kit"
    result = CliRunner().invoke(
        cli, ["bundle", "download", "-o", str(target)], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.stderr
    posts = [c for c in client.calls if c[0] == "POST"]
    assert posts[0] == ("POST", "/bundles", {})  # empty create body
    assert ("POST", "/bundles/b_auto", None) in client.calls
    assert (target / "README.md").read_text() == "hello\n"


def test_bundle_download_with_id_does_not_create(tmp_path):
    client = _BundleClient()
    target = tmp_path / "kit"
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b_given", "-o", str(target)],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.stderr
    assert all(c[1] != "/bundles" for c in client.calls)  # no create
    assert ("POST", "/bundles/b_given", None) in client.calls
    assert (target / "src" / "app.py").read_text() == "print(1)\n"


def test_bundle_download_default_extracts_into_name_dir(tmp_path, monkeypatch):
    client = _BundleClient(disposition='attachment; filename="ledgerflow.zip"')
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b1"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code == 0, result.stderr
    assert (tmp_path / "ledgerflow" / "README.md").read_text() == "hello\n"


def test_bundle_download_refuses_non_empty_dir(tmp_path):
    client = _BundleClient()
    target = tmp_path / "busy"
    target.mkdir()
    (target / "pre.txt").write_text("keep")
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b1", "-o", str(target)],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    assert "not empty" in result.stderr
    assert (target / "pre.txt").read_text() == "keep"


def test_bundle_download_zip_keeps_archive(tmp_path):
    client = _BundleClient()
    dest = tmp_path / "keep.zip"
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b1", "--zip", "-o", str(dest)],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.stderr
    assert dest.read_bytes() == FIXTURE_ZIP
    assert oct(dest.stat().st_mode & 0o777) == "0o600"


def test_bundle_download_zip_refuses_clobber(tmp_path):
    client = _BundleClient()
    dest = tmp_path / "exists.zip"
    dest.write_text("old-archive")
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b1", "--zip", "-o", str(dest)],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code != 0
    assert "already exists" in result.stderr
    assert dest.read_text() == "old-archive"


def test_bundle_download_streams_to_stdout(tmp_path):
    client = _BundleClient()
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b1", "-o", "-"],
        obj=_logged_in_context(tmp_path, client),
    )
    assert result.exit_code == 0, result.stderr
    assert result.stdout_bytes == FIXTURE_ZIP


def test_bundle_download_requires_login(tmp_path):
    client = _BundleClient()
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b1"], obj=_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "not logged in" in result.output
    # No request was made (login guard fires before any call).
    assert client.calls == []


def test_bundle_download_maps_404(tmp_path):
    client = _BundleClient(download_error=ApiError(404, "bundle_not_found"))
    result = CliRunner().invoke(
        cli, ["bundle", "download", "b1"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "bundle not found" in result.stderr


def test_bundle_download_challenge_failed_points_to_web(tmp_path):
    client = _BundleClient(create_error=ApiError(400, "challenge_failed"))
    result = CliRunner().invoke(
        cli, ["bundle", "download"], obj=_logged_in_context(tmp_path, client)
    )
    assert result.exit_code != 0
    assert "browser verification" in result.stderr


# --- README stays in sync ---------------------------------------------------


def test_readme_lists_the_trimmed_surface():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    for command in [
        "tripwire auth login",
        "tripwire auth logout",
        "tripwire auth status",
        "tripwire status",
        "tripwire canary create",
        "tripwire canary list",
        "tripwire canary show",
        "tripwire canary delete",
        "tripwire bundle download",
    ]:
        assert command in readme
    # Removed surface must not be advertised.
    for gone in ["whoami", "deactivate", "--expires", "--memo", "--timeout", "tripwire canaries"]:
        assert gone not in readme
