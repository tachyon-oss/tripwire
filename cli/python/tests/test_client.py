from __future__ import annotations

import json

import httpx
import pytest

from tripwire_cli.client import ApiClient, ApiError


def _client(handler, *, token: str | None = None, base_url="https://api.example") -> ApiClient:
    """An ApiClient wired to a MockTransport that calls ``handler`` per request.
    No network and no monkeypatching: the transport is injected directly."""
    transport = httpx.MockTransport(handler)
    return ApiClient(base_url=base_url, token=token, http_client=httpx.Client(transport=transport))


def test_get_parses_json_and_sets_auth_header():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(200, json={"canaries": []})

    client = _client(handler, token="tok", base_url="https://api.example/")
    assert client.list_canaries() == {"canaries": []}

    req = seen["request"]
    assert req.method == "GET"
    assert str(req.url) == "https://api.example/canary"
    assert req.headers["authorization"] == "Bearer tok"
    # GET carries no body, so no content-type.
    assert "content-type" not in req.headers


def test_empty_body_returns_empty_dict():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(200, content=b"")

    client = _client(handler)
    assert client.delete_canary("can_1") == {}
    assert seen["request"].method == "DELETE"
    assert str(seen["request"].url) == "https://api.example/canary/can_1"


def test_post_sends_json_body_and_content_type():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(
            200,
            json={
                "id": "can_1",
                "type": "aws_access_key",
                "status": "active",
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "sekret",
                "region": "us-east-1",
            },
        )

    client = _client(handler, token="t")
    result = client.create_canary({"type": "aws_access_key"})

    # The credential is inlined at the top level of the create response.
    assert result["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
    assert result["secret_access_key"] == "sekret"
    req = seen["request"]
    assert req.method == "POST"
    assert req.headers["content-type"] == "application/json"
    import json

    assert json.loads(req.content) == {"type": "aws_access_key"}


def test_get_returns_summary_without_credential():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(
            200,
            json={
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
            },
        )

    result = _client(handler, token="t").get_canary("can_1")
    for field in ("access_key_id", "secret_access_key", "region", "raw_token", "raw_key", "fqdn", "qtype"):
        assert field not in result
    assert result["id"] == "can_1"
    assert seen["request"].method == "GET"
    assert str(seen["request"].url) == "https://api.example/canary/can_1"


def test_delete_uses_delete_method():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(200, json={"id": "can_1"})

    _client(handler, token="t").delete_canary("can_1")
    assert seen["request"].method == "DELETE"
    assert str(seen["request"].url) == "https://api.example/canary/can_1"


def test_http_error_with_json_detail():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"detail": "label required"})

    with pytest.raises(ApiError) as exc:
        _client(handler, token="t").create_canary({"type": "dns_label"})
    assert exc.value.status == 400
    assert exc.value.detail == "label required"


@pytest.mark.parametrize(
    "status,detail",
    [(429, "canary_pending"), (502, "provisioning_failed")],
)
def test_create_failure_statuses_surface_as_api_error(status, detail):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"detail": detail})

    with pytest.raises(ApiError) as exc:
        _client(handler, token="t").create_canary({"type": "aws_access_key"})
    assert exc.value.status == status
    assert exc.value.detail == detail


def test_http_error_with_non_json_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"upstream boom")

    with pytest.raises(ApiError) as exc:
        _client(handler, token="t").list_canaries()
    assert exc.value.status == 500
    assert exc.value.detail == "upstream boom"


def test_connection_failure_is_clean_api_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("name resolution", request=request)

    client = ApiClient(
        base_url="https://nope.example",
        token="t",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ApiError) as exc:
        client.list_canaries()
    assert exc.value.status == 0
    assert "cannot reach https://nope.example" in exc.value.detail


# --- email login ------------------------------------------------------------


def test_login_start_posts_email():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(200, json={"status": "ok"})

    result = _client(handler).login_start("alice@example.com")

    assert result == {"status": "ok"}
    req = seen["request"]
    assert req.method == "POST"
    assert str(req.url) == "https://api.example/auth/login/start"
    assert json.loads(req.content) == {"email": "alice@example.com"}


def test_login_with_code_posts_email_and_code():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(
            200,
            json={
                "access_token": "tok",
                "token_type": "bearer",
                "expires_at": 1700000000,
                "user_id": "usr_alice",
                "role": "user",
            },
        )

    result = _client(handler).login_with_code("alice@example.com", "123456")

    assert result["access_token"] == "tok"
    req = seen["request"]
    assert req.method == "POST"
    assert str(req.url) == "https://api.example/auth/login"
    assert json.loads(req.content) == {"email": "alice@example.com", "code": "123456"}


def test_login_with_code_surfaces_invalid_code_as_api_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"detail": "invalid_or_expired_code"})

    with pytest.raises(ApiError) as exc:
        _client(handler).login_with_code("alice@example.com", "000000")
    assert exc.value.status == 400
    assert exc.value.detail == "invalid_or_expired_code"


# --- create read timeout ----------------------------------------------------


def test_create_uses_long_per_request_read_timeout():
    """The create POST must outlast the server's synchronous create wait
    (`CANARY_CREATE_WAIT_SECONDS`, 180s) so the client never abandons a
    request whose one-time credential reveal the server is still preparing.
    Connect stays short so an unreachable server still fails fast."""
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["timeout"] = request.extensions.get("timeout")
        return httpx.Response(
            200,
            json={"id": "can_1", "type": "aws_access_key", "status": "active"},
        )

    client = _client(handler, token="t")
    client.create_canary({"type": "aws_access_key"}, timeout=240.0)

    timeout = seen["timeout"]
    assert timeout["read"] == 240.0
    # Invariant: client read timeout strictly exceeds the server wait window.
    assert timeout["read"] > 180.0
    assert timeout["connect"] == 5.0


def test_default_client_uses_a_short_connect_timeout():
    # When ApiClient builds its own httpx.Client, connecting fails fast (5s)
    # even though the general read/write budget is longer.
    client = ApiClient(base_url="https://api.example", token="t")
    try:
        assert client._client.timeout.connect == 5.0
        assert client._client.timeout.read == 10.0
    finally:
        client.close()


# --- bundle -----------------------------------------------------------------


def test_create_bundle_posts_body():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(200, json={"status": "ready", "bundle_id": "b_1"})

    result = _client(handler, token="t").create_bundle({})

    assert result == {"status": "ready", "bundle_id": "b_1"}
    req = seen["request"]
    assert req.method == "POST"
    assert str(req.url) == "https://api.example/bundles"
    assert json.loads(req.content) == {}


def test_download_bundle_returns_headers_and_bytes():
    seen: dict = {}
    zip_bytes = b"PK\x03\x04 not-a-real-zip-but-binary"

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(
            200,
            content=zip_bytes,
            headers={"content-disposition": 'attachment; filename="kit.zip"'},
        )

    headers, buffer = _client(handler, token="t").download_bundle("b_1")

    assert buffer == zip_bytes
    assert headers.get("content-disposition") == 'attachment; filename="kit.zip"'
    req = seen["request"]
    assert req.method == "POST"
    assert str(req.url) == "https://api.example/bundles/b_1"


def test_download_bundle_raises_api_error_with_json_detail():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "bundle_not_found"})

    with pytest.raises(ApiError) as exc:
        _client(handler, token="t").download_bundle("b_missing")
    assert exc.value.status == 404
    assert exc.value.detail == "bundle_not_found"


def test_client_has_no_deactivate_method():
    # `canary disarm`/deactivate was removed from the CLI surface, so the client
    # no longer exposes it.
    assert not hasattr(ApiClient, "deactivate_canary")
