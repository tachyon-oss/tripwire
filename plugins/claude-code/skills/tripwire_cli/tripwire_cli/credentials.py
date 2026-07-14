"""Local credential cache for the Tripwire CLI.

The token and identity are kept in a single JSON file, by default
``~/.config/tripwire/credentials.json`` (honoring ``XDG_CONFIG_HOME``). The
server URL is stored only when it differs from the public default, so a normal
user's cache is just their token and identity.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path

# The public Tripwire API. A cache targeting this server omits the ``server``
# field entirely; only self-hosted / test targets are written.
DEFAULT_SERVER = "https://tripwire.so/api/v1"


@dataclass(frozen=True, kw_only=True)
class Credentials:
    user_id: str
    access_token: str
    expires_at: int
    # Stored only for non-default servers; ``None`` means the public default.
    server: str | None = None
    # Present for email-code logins; absent for caches written by older CLIs.
    email: str | None = None

    def resolved_server(self) -> str:
        """The effective API base URL: the stored server, or the public default."""
        return self.server or DEFAULT_SERVER

    def is_expired(self, now: float | None = None) -> bool:
        """Whether the cached token has passed its expiry. ``expires_at`` is epoch
        seconds (the backend sets it alongside the JWT ``exp`` claim)."""
        return self.expires_at <= (time.time() if now is None else now)


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
            raise NoCredentialsError("not logged in (run `tripwire auth login`)")
        data = json.loads(self.path.read_text())
        # Forward-compatible: keep only the fields this CLI knows about, so an
        # older CLI reading a cache written by a newer one does not crash on an
        # unexpected keyword argument. Also drops the legacy ``role`` field.
        known = {f.name for f in dataclasses.fields(Credentials)}
        return Credentials(**{k: v for k, v in data.items() if k in known})

    def try_load(self) -> Credentials | None:
        """The cached credentials, or None when there is no usable cache. Missing,
        unreadable, and corrupt files all mean the same thing: log in again. A
        TypeError is the "valid JSON, missing a required field" shape of corrupt."""
        try:
            return self.load()
        except (NoCredentialsError, ValueError, TypeError, OSError):
            return None

    def save(self, credentials: Credentials) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Omit optional fields that are unset (``server`` for the default target,
        # ``email`` when absent) so the file carries only what it needs.
        data = {k: v for k, v in asdict(credentials).items() if v is not None}
        self.path.write_text(json.dumps(data, indent=2))
        self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return self.path

    def clear(self) -> bool:
        if not self.path.exists():
            return False
        self.path.unlink()
        return True


def default_store() -> CredentialStore:
    return CredentialStore(default_path())
