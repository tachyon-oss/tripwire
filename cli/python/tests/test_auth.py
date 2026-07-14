from __future__ import annotations

import pytest
from click.testing import CliRunner

from tripwire_cli import credentials
from tripwire_cli.cli import Context, cli
from tripwire_cli.prompt import TtyPrompter

FUTURE = 1_900_000_000  # epoch seconds
PAST = 1_700_000_000
NOW = 1_800_000_000


def _creds(expires_at: int) -> credentials.Credentials:
    return credentials.Credentials(
        user_id="usr_1", access_token="tok", expires_at=expires_at
    )


def test_is_expired_false_for_future_token():
    assert _creds(FUTURE).is_expired(now=NOW) is False


def test_is_expired_true_for_past_token():
    assert _creds(PAST).is_expired(now=NOW) is True


def test_is_expired_true_for_a_null_expiry(tmp_path):
    # A cache with a null/garbage expiry must mean "log in again", never a crash.
    # The Node CLI shares this file and treats it the same way; a TypeError here
    # used to escape as a raw traceback.
    path = tmp_path / "credentials.json"
    path.write_text('{"user_id":"usr_1","access_token":"tok","expires_at":null}')
    cached = credentials.CredentialStore(path).try_load()
    assert cached is not None
    assert cached.is_expired() is True


def test_null_expiry_fails_cleanly_without_a_tty(tmp_path):
    store = credentials.CredentialStore(tmp_path / "credentials.json")
    store.path.write_text('{"user_id":"usr_1","access_token":"tok","expires_at":null}')
    obj = Context(
        store=store,
        client_factory=lambda server, token=None: FakeClient([]),
        prompter=FakePrompter([], tty=False),
    )
    result = CliRunner().invoke(cli, ["canary", "list", "--json"], obj=obj)
    assert result.exit_code != 0
    assert "tripwire auth login" in result.output
    assert not isinstance(result.exception, TypeError)


@pytest.mark.parametrize(
    "expires_at",
    [float("inf"), float("nan"), 1e17],
    ids=["infinity", "nan", "unrenderable-far-future"],
)
def test_is_expired_true_for_garbage_rather_than_never_expiring(expires_at):
    # These must not read as "a token that never expires". Infinity used to, and
    # rendering it in `auth status` then died with an OverflowError.
    assert _creds(expires_at).is_expired(now=NOW) is True


@pytest.mark.parametrize(
    "contents",
    ["null", "[]", '"nope"'],
    ids=["json-null", "json-array", "json-string"],
)
def test_try_load_returns_none_for_non_object_json(tmp_path, contents):
    # `.items()` on a non-dict used to escape as a raw AttributeError traceback.
    path = tmp_path / "credentials.json"
    path.write_text(contents)
    assert credentials.CredentialStore(path).try_load() is None


def test_try_load_returns_none_when_the_token_is_missing(tmp_path):
    # Both CLIs share this file and must agree on what "logged in" means.
    path = tmp_path / "credentials.json"
    path.write_text('{"user_id":"usr_1","expires_at":9999999999}')
    assert credentials.CredentialStore(path).try_load() is None


def test_tty_prompter_interactive_follows_stdin(tmp_path):
    # The guard that stops the CLI hanging on an invisible prompt in CI, in a
    # pipe, and inside the Claude Code plugin. Every other no-TTY test injects a
    # fake prompter, so without this nothing would catch this returning True.
    class _Stream:
        def __init__(self, tty: bool):
            self._tty = tty

        def isatty(self) -> bool:
            return self._tty

    assert TtyPrompter(stdin=_Stream(False)).interactive() is False
    assert TtyPrompter(stdin=_Stream(True)).interactive() is True


def test_try_load_returns_none_without_a_cache(tmp_path):
    store = credentials.CredentialStore(tmp_path / "credentials.json")
    assert store.try_load() is None


def test_try_load_returns_none_for_a_corrupt_cache(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text("{not json")
    # A half-written cache means "log in again", not a crash.
    assert credentials.CredentialStore(path).try_load() is None


def test_try_load_returns_the_cached_credentials(tmp_path):
    store = credentials.CredentialStore(tmp_path / "credentials.json")
    store.save(_creds(FUTURE))
    loaded = store.try_load()
    assert loaded is not None
    assert loaded.user_id == "usr_1"


# --- automatic login --------------------------------------------------------


class FakePrompter:
    """Scripted prompter: answers come from `answers`, in order."""

    def __init__(self, answers: list[str] | None = None, tty: bool = True):
        self.answers = list(answers or [])
        self.tty = tty
        self.asked: list[str] = []
        self.notices: list[str] = []

    def interactive(self) -> bool:
        return self.tty

    def ask(self, question: str, default: str | None = None) -> str:
        self.asked.append(question)
        if not self.answers:
            raise AssertionError(f"unexpected prompt: {question}")
        return self.answers.pop(0)

    def notify(self, line: str) -> None:
        self.notices.append(line)


class FakeClient:
    """Records the API calls a command makes; serves a successful login."""

    def __init__(self, calls: list[str]):
        self.calls = calls

    def login_start(self, email):
        self.calls.append("login_start")
        return {}

    def login_with_code(self, email, code):
        self.calls.append("login_with_code")
        return {"user_id": "usr_new", "access_token": "tok_new", "expires_at": FUTURE}

    def list_canaries(self):
        self.calls.append("list_canaries")
        return {"canaries": []}


def _context(tmp_path, prompter, calls) -> Context:
    store = credentials.CredentialStore(tmp_path / "credentials.json")
    return Context(
        store=store,
        client_factory=lambda server, token=None: FakeClient(calls),
        prompter=prompter,
    )


def test_signs_in_then_runs_the_requested_command(tmp_path):
    calls: list[str] = []
    prompter = FakePrompter(["me@co.com", "123456"])
    obj = _context(tmp_path, prompter, calls)

    result = CliRunner().invoke(cli, ["canary", "list", "--json"], obj=obj)

    assert result.exit_code == 0, result.output
    assert calls == ["login_start", "login_with_code", "list_canaries"]
    assert prompter.asked == ["email", "code"]
    assert "not logged in" in prompter.notices[0]
    assert obj.store.try_load().user_id == "usr_new"


def test_re_signs_in_when_the_cached_token_expired(tmp_path):
    calls: list[str] = []
    prompter = FakePrompter(["me@co.com", "123456"])
    obj = _context(tmp_path, prompter, calls)
    obj.store.save(
        credentials.Credentials(
            user_id="usr_old", access_token="stale", expires_at=PAST
        )
    )

    result = CliRunner().invoke(cli, ["canary", "list", "--json"], obj=obj)

    assert result.exit_code == 0, result.output
    assert calls == ["login_start", "login_with_code", "list_canaries"]
    assert "expired" in prompter.notices[0]


def test_uses_a_valid_cached_token_without_prompting(tmp_path):
    calls: list[str] = []
    prompter = FakePrompter([])
    obj = _context(tmp_path, prompter, calls)
    obj.store.save(_creds(FUTURE))

    result = CliRunner().invoke(cli, ["canary", "list", "--json"], obj=obj)

    assert result.exit_code == 0, result.output
    assert calls == ["list_canaries"]
    assert prompter.asked == []


def test_signs_in_over_a_corrupt_cache(tmp_path):
    # A half-written cache must land the user in the sign-in flow, not surface as
    # a JSON parse error after we have already said "signing you in first".
    calls: list[str] = []
    prompter = FakePrompter(["me@co.com", "123456"])
    obj = _context(tmp_path, prompter, calls)
    (tmp_path / "credentials.json").write_text("{not json")

    result = CliRunner().invoke(cli, ["canary", "list", "--json"], obj=obj)

    assert result.exit_code == 0, result.output
    assert calls == ["login_start", "login_with_code", "list_canaries"]
    assert obj.store.try_load().user_id == "usr_new"


def test_fails_fast_without_a_tty(tmp_path):
    calls: list[str] = []
    prompter = FakePrompter([], tty=False)
    obj = _context(tmp_path, prompter, calls)

    result = CliRunner().invoke(cli, ["canary", "list", "--json"], obj=obj)

    assert result.exit_code != 0
    assert "tripwire auth login" in result.output
    assert calls == []
    assert prompter.asked == []


# --- the auth group ---------------------------------------------------------


def test_auth_status_prints_identity_and_never_prompts(tmp_path):
    prompter = FakePrompter([])
    obj = _context(tmp_path, prompter, [])
    obj.store.save(
        credentials.Credentials(
            user_id="usr_1",
            access_token="tok",
            expires_at=FUTURE,
            email="me@co.com",
        )
    )

    result = CliRunner().invoke(cli, ["auth", "status"], obj=obj)

    assert result.exit_code == 0, result.output
    assert "usr_1" in result.output
    assert "me@co.com" in result.output
    assert "session: valid until" in result.output
    assert prompter.asked == []


def test_auth_status_errors_when_logged_out(tmp_path):
    prompter = FakePrompter([])
    obj = _context(tmp_path, prompter, [])

    result = CliRunner().invoke(cli, ["auth", "status"], obj=obj)

    assert result.exit_code != 0
    assert "tripwire auth login" in result.output
    assert prompter.asked == []


def test_auth_logout_never_prompts(tmp_path):
    prompter = FakePrompter([], tty=False)
    obj = _context(tmp_path, prompter, [])
    result = CliRunner().invoke(cli, ["auth", "logout"], obj=obj)
    assert result.exit_code == 0
    assert prompter.asked == []


def test_top_level_login_reports_the_move(tmp_path):
    obj = _context(tmp_path, FakePrompter([]), [])
    result = CliRunner().invoke(cli, ["login"], obj=obj)
    assert result.exit_code != 0
    assert "`tripwire login` moved to `tripwire auth login`" in result.output


def test_login_is_hidden_from_help(tmp_path):
    result = CliRunner().invoke(cli, ["--help"])
    assert "auth" in result.output
    # The migration stub exists but must not be advertised.
    assert "\n  login" not in result.output
