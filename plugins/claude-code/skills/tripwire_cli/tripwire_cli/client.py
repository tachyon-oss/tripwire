"""HTTP client for the Tripwire REST API."""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

DEFAULT_TIMEOUT = 10.0

# Connecting should fail fast even when a single request is allowed a long read
# window, so an unreachable server never hangs for the full read timeout.
CONNECT_TIMEOUT = 5.0

# `POST /canary` is synchronous and some types take a little while to provision;
# the server waits up to ~180s before it gives up. The client read timeout MUST
# stay above that window: if the client abandons the request first, the server
# still creates the canary, the one-time credential reveal is lost, and the
# per-type quota is consumed with no recovery.
CREATE_READ_TIMEOUT = 240.0


class ApiError(Exception):
    """A non-2xx response, or a failure to reach the server (``status == 0``)."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class ApiClient:
    """Thin client over the Tripwire REST API.

    Pass ``http_client`` to supply your own configured ``httpx.Client``
    (handy for tests and custom transports); otherwise one is created.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        http_client: httpx.Client | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        # Short connect everywhere (a hung connect should fail fast); the
        # read/write/pool budget is ``timeout``. The create path raises its
        # read budget per-request via ``_request(timeout=...)``.
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT)
        )

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {}
        if timeout is not None:
            # Per-request override: long read window, short connect so an
            # unreachable server still fails fast.
            kwargs["timeout"] = httpx.Timeout(timeout, connect=CONNECT_TIMEOUT)
        try:
            response = self._client.request(
                method,
                self.base_url + path,
                json=payload,
                headers=self._headers(),
                **kwargs,
            )
        except httpx.RequestError as exc:
            raise ApiError(0, f"cannot reach {self.base_url}: {exc}") from exc
        if response.is_error:
            raise ApiError(response.status_code, _error_detail(response))
        if not response.content:
            return {}
        return response.json()

    def login_start(self, email: str) -> dict[str, Any]:
        """Begin an email-code login: the server emails a 6-digit code. The
        response is intentionally neutral (``{"status": "ok"}``) and never
        reveals whether the address is known. This endpoint is IP rate-limited
        (~5 starts / 10 min, plus a new-user cap), returning
        ``429 rate_limited`` when exceeded, so call it once per login and
        re-prompt for the code in-band on failure."""
        return self._request("POST", "/auth/login/start", {"email": email})

    def login_with_code(self, email: str, code: str) -> dict[str, Any]:
        """Exchange an emailed 6-digit code for a token. A wrong/expired/used
        code returns ``400 invalid_or_expired_code``. A ``5xx`` here can leave
        the code consumed server-side, so the caller treats it as spent and
        sends the user back to request a fresh code rather than retrying."""
        return self._request("POST", "/auth/login", {"email": email, "code": code})

    def list_canaries(self) -> dict[str, Any]:
        return self._request("GET", "/canary")

    def create_canary(
        self, payload: dict[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        """Create a canary. The response carries the credential inline; this is
        the only time it is returned, so capture it from the result.

        ``timeout`` is the read timeout for this one request (defaults to
        ``CREATE_READ_TIMEOUT``). It must stay above the server's synchronous
        create wait window, or the client gives up while the server is still
        provisioning and the one-time reveal is lost."""
        return self._request(
            "POST",
            "/canary",
            payload,
            timeout=CREATE_READ_TIMEOUT if timeout is None else timeout,
        )

    def get_canary(self, canary_id: str) -> dict[str, Any]:
        return self._request("GET", f"/canary/{canary_id}")

    def deactivate_canary(self, canary_id: str) -> dict[str, Any]:
        return self._request("POST", f"/canary/{canary_id}/deactivate")

    def delete_canary(self, canary_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/canary/{canary_id}")


def _error_detail(response: httpx.Response) -> str:
    """Best-effort human-readable detail from an error response: the JSON
    ``detail`` field when present, else the raw body or status reason."""
    try:
        body = response.json()
    except ValueError:
        return response.text or response.reason_phrase
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return response.text or response.reason_phrase
