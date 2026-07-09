from __future__ import annotations

import json

import pytest

from tripwire_cli import credentials
from tripwire_cli.credentials import CredentialStore, Credentials, NoCredentialsError


def _store(tmp_path) -> CredentialStore:
    return CredentialStore(tmp_path / "tripwire" / "credentials.json")


def test_credentials_round_trip(tmp_path):
    store = _store(tmp_path)

    with pytest.raises(NoCredentialsError):
        store.load()

    creds = Credentials(
        server="https://tripwire.example.com",
        user_id="usr_alice",
        access_token="abc.def.ghi",
        expires_at=1700000000,
    )
    path = store.save(creds)
    assert path.exists()
    # Token file is owner read/write only.
    assert oct(path.stat().st_mode & 0o777) == "0o600"

    assert store.load() == creds

    assert store.clear() is True
    assert store.clear() is False


def test_credentials_carry_optional_email(tmp_path):
    store = _store(tmp_path)
    creds = Credentials(
        server="https://tripwire.example.com",
        user_id="usr_alice",
        access_token="abc.def.ghi",
        expires_at=1700000000,
        email="alice@example.com",
    )
    store.save(creds)
    loaded = store.load()
    assert loaded.email == "alice@example.com"
    assert loaded == creds


def test_default_server_omitted_from_file_and_role_dropped(tmp_path):
    # A default-target login stores no `server` field (it resolves to the public
    # default on load), and a legacy `role` field is dropped.
    store = _store(tmp_path)
    creds = Credentials(
        user_id="usr_alice",
        access_token="abc.def.ghi",
        expires_at=1700000000,
        email="alice@example.com",
    )
    store.save(creds)
    on_disk = json.loads(store.path.read_text())
    assert "server" not in on_disk
    assert "role" not in on_disk
    loaded = store.load()
    assert loaded.server is None
    assert loaded.resolved_server() == credentials.DEFAULT_SERVER


def test_email_defaults_to_none_for_legacy_cache(tmp_path):
    # An older cache, written before the email field existed, has no `email`
    # key. Loading it must still succeed with email defaulting to None.
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(
        json.dumps(
            {
                "server": "https://tripwire.example.com",
                "user_id": "usr_alice",
                "access_token": "abc.def.ghi",
                "expires_at": 1700000000,
                "role": "user",
            }
        )
    )
    loaded = store.load()
    assert loaded.email is None
    assert loaded.user_id == "usr_alice"


def test_load_tolerates_unknown_keys_from_a_newer_cli(tmp_path):
    # An older CLI must not crash reading a cache written by a newer CLI that
    # added fields it does not know about.
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(
        json.dumps(
            {
                "server": "https://tripwire.example.com",
                "user_id": "usr_alice",
                "access_token": "abc.def.ghi",
                "expires_at": 1700000000,
                "role": "user",
                "email": "alice@example.com",
                "some_future_field": {"nested": True},
                "another_new_one": 42,
            }
        )
    )
    loaded = store.load()
    assert loaded.email == "alice@example.com"
    assert loaded.server == "https://tripwire.example.com"
    assert not hasattr(loaded, "some_future_field")


def test_default_path_honors_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert credentials.default_path() == tmp_path / "tripwire" / "credentials.json"
    assert credentials.default_store().path == credentials.default_path()
