"""Coverage for api/middleware.py: the entire authN/authZ/rate-limit boundary."""

import asyncio

import httpx
import pytest
from starlette.requests import Request

import config
from api.middleware import SecurityMiddleware


def _client_id(headers: dict, client: tuple[str, int], trust_proxy: bool) -> str:
    config.TRUST_PROXY_HEADERS = trust_proxy
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": client,
    }
    return SecurityMiddleware._client_id(Request(scope))


async def _get(path: str, *, headers: dict | None = None, client_ip: str):
    from api.server import app

    transport = httpx.ASGITransport(app=app, client=(client_ip, 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        return await c.get(path, headers=headers or {})


@pytest.fixture(autouse=True)
def _restore_config():
    original_keys = config.API_KEYS
    original_trust_proxy = config.TRUST_PROXY_HEADERS
    original_rate_limit = config.RATE_LIMIT_REQUESTS_PER_MIN
    yield
    config.API_KEYS = original_keys
    config.TRUST_PROXY_HEADERS = original_trust_proxy
    config.RATE_LIMIT_REQUESTS_PER_MIN = original_rate_limit


def test_client_id_ignores_proxy_header_by_default():
    client_id = _client_id(
        {"x-forwarded-for": "1.2.3.4, 5.6.7.8"},
        client=("9.9.9.9", 1),
        trust_proxy=False,
    )
    assert client_id == "9.9.9.9"


def test_client_id_honors_proxy_header_when_trusted():
    client_id = _client_id(
        {"x-forwarded-for": "1.2.3.4, 5.6.7.8"},
        client=("9.9.9.9", 1),
        trust_proxy=True,
    )
    assert client_id == "1.2.3.4"


def test_missing_key_returns_401_when_keys_configured():
    config.API_KEYS = {"expected-secret"}
    resp = asyncio.run(
        _get("/api/v1/operations/metrics", client_ip="203.0.113.10")
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "valid API key required"
    assert "X-Request-ID" in resp.headers


def test_wrong_key_returns_401():
    config.API_KEYS = {"expected-secret"}
    resp = asyncio.run(
        _get(
            "/api/v1/operations/metrics",
            headers={"X-API-Key": "wrong-key"},
            client_ip="203.0.113.11",
        )
    )
    assert resp.status_code == 401


def test_correct_key_returns_200():
    config.API_KEYS = {"expected-secret"}
    resp = asyncio.run(
        _get(
            "/api/v1/operations/metrics",
            headers={"X-API-Key": "expected-secret"},
            client_ip="203.0.113.12",
        )
    )
    assert resp.status_code == 200


def test_bearer_token_is_also_accepted():
    config.API_KEYS = {"expected-secret"}
    resp = asyncio.run(
        _get(
            "/api/v1/operations/metrics",
            headers={"Authorization": "Bearer expected-secret"},
            client_ip="203.0.113.13",
        )
    )
    assert resp.status_code == 200


def test_health_and_ready_bypass_auth_even_with_keys_set():
    config.API_KEYS = {"expected-secret"}
    health = asyncio.run(_get("/api/v1/health", client_ip="203.0.113.14"))
    ready = asyncio.run(_get("/api/v1/ready", client_ip="203.0.113.14"))
    assert health.status_code == 200
    assert ready.status_code in (200, 503)  # unauthenticated either way, no 401


def test_empty_api_keys_disables_auth_entirely():
    config.API_KEYS = set()
    resp = asyncio.run(_get("/api/v1/operations/metrics", client_ip="203.0.113.15"))
    assert resp.status_code == 200


def test_rate_limit_trips_after_configured_requests():
    config.API_KEYS = {"expected-secret"}
    config.RATE_LIMIT_REQUESTS_PER_MIN = 3
    headers = {"X-API-Key": "expected-secret"}
    client_ip = "203.0.113.16"

    statuses = [
        asyncio.run(
            _get("/api/v1/operations/metrics", headers=headers, client_ip=client_ip)
        ).status_code
        for _ in range(4)
    ]
    assert statuses == [200, 200, 200, 429]


def test_rate_limit_is_scoped_per_client():
    config.API_KEYS = {"expected-secret"}
    config.RATE_LIMIT_REQUESTS_PER_MIN = 1
    headers = {"X-API-Key": "expected-secret"}

    first = asyncio.run(
        _get("/api/v1/operations/metrics", headers=headers, client_ip="203.0.113.20")
    )
    second_client = asyncio.run(
        _get("/api/v1/operations/metrics", headers=headers, client_ip="203.0.113.21")
    )
    assert first.status_code == 200
    assert second_client.status_code == 200
