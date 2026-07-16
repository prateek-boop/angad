"""The app-level unhandled-error boundary: JSON 500s that never leak internals."""

import asyncio

import httpx
import pytest

import config
from api.metrics import metrics
from api.server import app


@pytest.fixture(autouse=True)
def _open_auth():
    original_keys = config.API_KEYS
    config.API_KEYS = set()
    yield
    config.API_KEYS = original_keys


async def _request(method: str, path: str, **kwargs):
    transport = httpx.ASGITransport(
        app=app, raise_app_exceptions=False, client=("203.0.113.99", 1)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        return await c.request(method, path, **kwargs)


def test_health_reports_installed_version():
    resp = asyncio.run(_request("GET", "/api/v1/health"))
    assert resp.status_code == 200
    assert resp.json()["version"] == config.VERSION


def test_unhandled_error_returns_json_500_with_request_id(monkeypatch):
    import api.routes.scan as scan_route

    def boom():
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(scan_route, "get_orchestrator", boom)
    errors_before = metrics.snapshot()["counters"].get("errors_total", 0)

    resp = asyncio.run(
        _request("POST", "/api/v1/scan", json={"url": "https://example.com"})
    )

    assert resp.status_code == 500
    body = resp.json()
    assert body["detail"] == "internal server error"
    assert body["request_id"]
    assert "secret internal detail" not in resp.text
    assert resp.headers["X-Request-ID"] == body["request_id"]
    assert metrics.snapshot()["counters"].get("errors_total", 0) == errors_before + 1
