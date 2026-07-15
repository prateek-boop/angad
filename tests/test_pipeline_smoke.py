"""End-to-end smoke test: real trained model, real API route, no mocks.
Requires a trained model at config.MODEL_PATH (run train_model first)."""

import os
import asyncio

import httpx
import pytest

import config


async def _post(path: str, payload: dict):
    from api.server import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(path, json=payload)


@pytest.mark.skipif(
    not os.path.exists(config.MODEL_PATH), reason="model not trained yet"
)
def test_scan_endpoint_returns_valid_contract():
    resp = asyncio.run(
        _post("/api/v1/scan", {"url": "https://www.google.com/search?q=test"})
    )
    assert resp.status_code == 200

    body = resp.json()
    assert body["category"] in config.THREAT_CLASSES
    assert set(body["probabilities"].keys()) == set(config.THREAT_CLASSES)
    assert abs(sum(body["probabilities"].values()) - 1.0) < 1e-3
    assert isinstance(body["blocked"], bool)
    assert body["threat_level"] in config.THREAT_LEVEL_THRESHOLDS


@pytest.mark.skipif(
    not os.path.exists(config.MODEL_PATH), reason="model not trained yet"
)
def test_batch_scan_endpoint():
    resp = asyncio.run(
        _post(
            "/api/v1/scan/batch",
            {
                "urls": [
                    "https://www.google.com",
                    "http://paypal-verify.suspicious.xyz/login",
                ]
            },
        )
    )
    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 2
