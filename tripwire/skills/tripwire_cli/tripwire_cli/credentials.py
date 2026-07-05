"""Local credential cache for the Tripwire CLI.

The token, server URL, and identity are kept in a single JSON file, by default
``~/.config/tripwire/credentials.json`` (honoring ``XDG_CONFIG_HOME``).
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, kw_only=True)
class Credentials:
    server: str
    user_id: str
    access_token: str
    expires_at: int
    role: str
    # Optional: present for email-code logins, absent for operator
    # (user-id/password) logins and for caches written by older CLIs.
    email: str | None = None


class NoCredentialsError(Exception):
    pass


def default_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "tripwire" / "credentials.json"


@dataclass(frozen=True)
class CredentialStore:
    """Read/write the cached credentials at ``path``."""

    path: Path

    def load(self) -> Credentials:
        if not self.path.exists():
            raise NoCredentialsError("not logged in (run `tripwire login`)")
        data = json.loads(self.path.read_text())
        # Forward-compatible: keep only the fields this CLI knows about, so an
        # older CLI reading a cache written by a newer one does not crash on an
        # unexpected keyword argument.
        known = {f.name for f in dataclasses.fields(Credentials)}
        return Credentials(**{k: v for k, v in data.items() if k in known})

    def save(self, credentials: Credentials) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(asdict(credentials), indent=2))
        self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return self.path

    def clear(self) -> bool:
        if not self.path.exists():
            return False
        self.path.unlink()
        return True


def default_store() -> CredentialStore:
    return CredentialStore(default_path())
