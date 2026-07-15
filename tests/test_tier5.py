import hashlib
import hmac
import json

import numpy as np
import pytest

import config
from ml_engine.fetch.ssrf_guard import SSRFBlocked
from ml_engine.tier5.calibration import TemperatureCalibrator
from ml_engine.tier5.drift import DriftMonitor
from ml_engine.tier5.ensemble import EvidenceEnsemble
from ml_engine.tier5.feedback import FeedbackStore, redact_url
from ml_engine.tier5.webhooks import WebhookDispatcher, WebhookStore


def test_temperature_calibration_round_trip_and_normalization(tmp_path):
    probabilities = np.array(
        [
            [0.99, 0.0025, 0.0025, 0.0025, 0.0025],
            [0.99, 0.0025, 0.0025, 0.0025, 0.0025],
            [0.01, 0.96, 0.01, 0.01, 0.01],
            [0.01, 0.01, 0.96, 0.01, 0.01],
        ]
    )
    labels = np.array([0, 1, 1, 2])
    calibrator = TemperatureCalibrator().fit(probabilities, labels)
    transformed = calibrator.transform(probabilities)
    assert transformed.shape == probabilities.shape
    assert np.allclose(transformed.sum(axis=1), 1.0)
    assert calibrator.temperature > 1.0

    path = tmp_path / "calibration.json"
    calibrator.save(str(path))
    loaded = TemperatureCalibrator.load(str(path))
    assert loaded.temperature == pytest.approx(calibrator.temperature)
    assert np.allclose(loaded.transform(probabilities), transformed)


def test_evidence_ensemble_exact_feed_and_html_override():
    base = {name: 0.05 for name in config.THREAT_CLASSES}
    base["safe"] = 0.8
    result = EvidenceEnsemble().fuse(base, reputation={"blocklist_hit": "urlhaus"})
    assert result.category == "malware"
    assert result.risk_score > 0.99
    assert result.contributions[0].severity == "critical"

    phishing = EvidenceEnsemble().fuse(
        base,
        html={
            "has_password_field": True,
            "form_domain_mismatch": True,
            "title_brand_mismatch": True,
        },
    )
    assert phishing.category == "phishing"
    assert phishing.probabilities["phishing"] > base["phishing"]


def test_feedback_store_redacts_secrets_and_links_scan(tmp_path):
    path = tmp_path / "feedback.sqlite3"
    store = FeedbackStore(str(path))
    url = (
        "https://user:password@example.com/reset?token=secret&email=a@example.com#frag"
    )
    redacted = redact_url(url)
    assert "password" not in redacted
    assert "secret" not in redacted
    assert "frag" not in redacted
    assert "REDACTED" in redacted

    probabilities = {name: 0.2 for name in config.THREAT_CLASSES}
    store.record_scan(
        scan_id="scan-1",
        url=url,
        depth="tier0",
        predicted_label="phishing",
        probabilities=probabilities,
        evidence={},
    )
    feedback_id = store.submit(
        scan_id="scan-1",
        correct_label="safe",
        notes=" false positive ",
        submitted_by="analyst@example.com",
    )
    assert feedback_id == 1
    assert store.summary()["known_corrections"] == 1


def test_drift_monitor_detects_large_shift(tmp_path):
    monitor = DriftMonitor(
        str(tmp_path / "drift.sqlite3"), baseline_window=10, check_window=5
    )
    safe_probs = {name: 0.025 for name in config.THREAT_CLASSES}
    safe_probs["safe"] = 0.9
    threat_probs = {name: 0.025 for name in config.THREAT_CLASSES}
    threat_probs["phishing"] = 0.9
    for index in range(10):
        monitor.record(
            scan_id=f"base-{index}",
            predicted_label="safe",
            risk_score=0.1,
            features=[0.0] * 41,
            probabilities=safe_probs,
        )
    for index in range(5):
        monitor.record(
            scan_id=f"current-{index}",
            predicted_label="phishing",
            risk_score=0.9,
            features=[10.0] * 41,
            probabilities=threat_probs,
        )
    report = monitor.report()
    assert report["status"] == "alert"
    assert report["drift_detected"] is True
    assert report["feature_alerts"]


def test_signed_webhook_delivery_and_ssrf_registration(tmp_path):
    def public_resolver(host, port):
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    store = WebhookStore(str(tmp_path / "webhooks.sqlite3"))
    secret = "this-is-a-long-test-secret"
    webhook_id = store.register(
        url="https://hooks.example.com/shieldnet",
        secret=secret,
        min_threat_level="high",
        resolver=public_resolver,
    )
    assert webhook_id
    observed = {}

    class Response:
        status_code = 204

    def requester(url, **kwargs):
        observed.update(kwargs)
        return Response()

    dispatcher = WebhookDispatcher(
        store=store, requester=requester, resolver=public_resolver
    )
    deliveries = dispatcher.dispatch(
        "threat.detected", {"scan_id": "scan-1"}, "critical"
    )
    assert deliveries[0]["success"] is True
    signature = observed["headers"]["X-ShieldNet-Signature"].removeprefix("sha256=")
    expected = hmac.new(secret.encode(), observed["data"], hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, expected)
    assert json.loads(observed["data"])["data"]["scan_id"] == "scan-1"

    def private_resolver(host, port):
        return [(2, 1, 6, "", ("127.0.0.1", 0))]

    with pytest.raises(SSRFBlocked):
        store.register(
            url="https://localhost/hook",
            secret=secret,
            resolver=private_resolver,
        )
