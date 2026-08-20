import logging
import os
import socket
import struct
import threading
from types import SimpleNamespace

import numpy as np
import pytest

import config
from netguard.ai_engine import AIEngine
from netguard.constants import KNOWN_MALWARE_JA3
from netguard.database import ReputationDB
from netguard.decision_engine import DecisionEngine
from netguard.feature_extractor import FeatureExtractor
from netguard.isolation_forest import IsolationForestDetector
from netguard.main import NetGuard
from netguard.netlink_parser import NetlinkParser


def test_ai_engine_reports_git_lfs_pointer_as_missing_artifact(tmp_path, caplog):
    pointer = tmp_path / "classifier.pkl"
    pointer.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:abc\n"
        "size 123\n"
    )
    engine = AIEngine.__new__(AIEngine)
    engine.logger = logging.getLogger("test.ai_engine")

    assert engine._load_pickle_artifact(str(pointer)) is None
    assert "Git LFS pointer" in caplog.text


def test_payload_classifier_does_not_treat_tls_client_hello_as_content():
    class UnexpectedClassifier:
        def predict_proba(self, _features):
            raise AssertionError("TLS bytes must not be sent to the payload model")

    engine = AIEngine.__new__(AIEngine)
    engine.payload_classifier = UnexpectedClassifier()
    verdict = {"risk_score": 0.1, "classification": "NORMAL", "reasons": []}

    result = engine._blend_payload_classifier(verdict, b"\x16\x03\x01\x00\x20")

    assert result["risk_score"] == 0.1
    assert result["payload_inspection"] == "unavailable_tls"


def test_payload_models_are_one_ensemble_signal():
    class FixedForest:
        def predict_proba(self, _vector):
            return np.asarray([[0.1, 0.9]])

    class IdentityScaler:
        def transform(self, vector):
            return vector

    class FixedDeepModel:
        def __call__(self, _vector, training=False):
            assert training is False
            return np.asarray([[0.7]])

    engine = AIEngine.__new__(AIEngine)
    engine.logger = logging.getLogger("test.payload_ensemble")
    engine.payload_classifier = FixedForest()
    engine.deep_payload_model = FixedDeepModel()
    engine.deep_payload_scaler = IdentityScaler()
    engine._payload_inference_lock = threading.Lock()
    verdict = {
        "risk_score": 0.1,
        "classification": "SAFE_WEB",
        "confidence": 0.8,
        "tier": 1,
        "reasons": [],
    }

    result = engine._blend_payload_classifier(
        verdict, b"GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )

    assert result["payload_model_probabilities"] == {
        "random_forest": pytest.approx(0.9),
        "deep": pytest.approx(0.7),
    }
    assert result["payload_attack_probability"] == pytest.approx(0.8)
    assert result["reasons"] == ["supervised_payload_model"]


def _verdict(risk, reasons=()):
    return {
        "risk_score": risk,
        "classification": "SUSPICIOUS",
        "confidence": 0.9,
        "reasons": list(reasons),
    }


def test_single_url_signal_never_hard_blocks(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(0.99, reasons=["shieldnet_domain_phishing"])
    action, reason = engine.evaluate_verdict("test-uid", verdict)
    assert action == "WARN"
    assert "corroboration" in reason.lower()
    assert engine._get_strikes("test-uid") == 0


def test_unverified_url_model_is_telemetry_only():
    engine = AIEngine.__new__(AIEngine)
    result = engine._blend_url_reputation(
        {"risk_score": 0.1, "classification": "NORMAL", "reasons": []},
        {
            "category": "phishing",
            "risk_score": 0.97,
            "enforcement_authorized": False,
        },
    )

    assert result["risk_score"] == 0.1
    assert result["classification"] == "NORMAL"
    assert result["reasons"] == []
    assert result["url_model_only"] is True
    assert result["url_model_observation"] == {
        "category": "phishing",
        "risk_score": 0.97,
        "reasons": [],
    }


def test_unverified_url_model_cannot_corroborate_payload_model(tmp_path):
    ai_engine = AIEngine.__new__(AIEngine)
    verdict = ai_engine._blend_url_reputation(
        {
            "risk_score": 0.95,
            "classification": "PAYLOAD_ATTACK",
            "confidence": 0.95,
            "reasons": ["supervised_payload_model"],
        },
        {
            "category": "scam",
            "risk_score": 0.99,
            "enforcement_authorized": False,
        },
    )

    action, reason = DecisionEngine(
        ReputationDB(str(tmp_path / "decision.db"))
    ).evaluate_verdict("test-uid", verdict)

    assert action == "WARN"
    assert "corroboration" in reason.lower()


def test_single_signal_at_warn_grade_is_allowed_without_strike(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(0.80, reasons=["shieldnet_domain_scam"])
    action, reason = engine.evaluate_verdict("test-uid", verdict)
    assert action == "ALLOW"
    assert "single-signal" in reason.lower()
    assert engine._get_strikes("test-uid") == 0


def test_url_plus_correlated_rule_signal_does_not_block(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(0.99, reasons=["shieldnet_domain_phishing", "risky_tld"])
    action, reason = engine.evaluate_verdict("test-uid", verdict)
    assert action == "WARN"
    assert "corroboration" in reason.lower()


def test_url_plus_payload_signal_hard_blocks(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(
        0.99,
        reasons=["shieldnet_domain_scam", "supervised_payload_model"],
    )
    verdict["payload_attack_probability"] = 0.9
    action, reason = engine.evaluate_verdict("test-uid", verdict)
    assert action == "BLOCK"


def test_url_plus_unvalidated_anomaly_signal_does_not_block(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(
        0.99,
        reasons=["shieldnet_model_scam", "isolation_forest_anomaly"],
    )
    action, reason = engine.evaluate_verdict("test-uid", verdict)

    assert action == "WARN"
    assert "corroboration" in reason.lower()


def test_verified_shieldnet_evidence_hard_blocks(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(0.99, reasons=["shieldnet_verified_malware"])

    action, _ = engine.evaluate_verdict("test-uid", verdict)

    assert action == "BLOCK"


def test_ja3_signature_alone_hard_blocks(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(0.95, reasons=["ja3_match:trickbot"])
    action, reason = engine.evaluate_verdict("test-uid", verdict)
    assert action == "BLOCK"


def test_corroboration_hold_does_not_add_strikes(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    verdict = _verdict(0.99, reasons=["shieldnet_domain_scam"])
    action, reason = engine.evaluate_verdict("test-uid", verdict)
    assert action == "WARN"
    assert engine._get_strikes("test-uid") == 0
    action2, _ = engine.evaluate_verdict("test-uid", _verdict(0.99, reasons=["shieldnet_domain_scam"]))
    assert action2 == "WARN"
    assert engine._get_strikes("test-uid") == 0


def test_historical_strikes_cannot_turn_model_only_signal_into_block(tmp_path):
    engine = DecisionEngine(ReputationDB(str(tmp_path / "decision.db")))
    for _ in range(engine.strike_limit):
        engine._add_strike("test-uid")

    action, reason = engine.evaluate_verdict(
        "test-uid",
        _verdict(0.8, reasons=["shieldnet_model_scam"]),
    )

    assert action == "ALLOW"
    assert "single-signal" in reason.lower()


@pytest.mark.skipif(
    not os.path.exists(config.MODEL_PATH), reason="ShieldNet model not trained yet"
)
def test_real_netguard_proxy_callback_relays_legitimate_tls_and_blocks_known_ja3(
    tmp_path,
):
    guard = NetGuard(db_path=str(tmp_path / "live-policy.sqlite3"))
    guard.url_reputation.orchestrator.persist = False
    guard.dashboard.emit_verdict = lambda *args, **kwargs: None
    callback = guard.proxy._block_check
    assert callback is not None

    legitimate_hosts = [
        "www.google.com",
        "api.github.com",
        "copilot-proxy.githubusercontent.com",
        "open.spotify.com",
        "go-updater.brave.com",
        "amazon.com",
        "cloudflare.com",
        "login.microsoftonline.com",
        "registry.npmjs.org",
        "files.pythonhosted.org",
    ]
    for round_number in (1, 2):
        for index, host in enumerate(legitimate_hosts):
            blocked, reason = callback(
                {
                    "client_ip": "10.20.30.40",
                    "client_port": 50000 + index,
                    "dst_ip": f"198.51.100.{index + 1}",
                    "dst_port": 443,
                    "protocol": "TCP",
                    "sni": host,
                    "ja3": "browser-ja3-not-on-threat-list",
                    "tls_version": "1.3",
                    "cipher_count": 18,
                    "extension_count": 12,
                    "initial_payload": b"\x16\x03\x01\x00\x20",
                }
            )
            assert blocked is False, f"round {round_number}: {host}: {reason}"

    assert guard.decision_engine._get_strikes("10.20.30.40") == 0

    malware_ja3, malware_family = next(iter(KNOWN_MALWARE_JA3.items()))
    blocked, reason = callback(
        {
            "client_ip": "10.20.30.99",
            "client_port": 51000,
            "dst_ip": "203.0.113.99",
            "dst_port": 443,
            "protocol": "TCP",
            "sni": "www.google.com",
            "ja3": malware_ja3,
            "tls_version": "1.2",
            "cipher_count": 4,
            "extension_count": 3,
            "initial_payload": b"\x16\x03\x01\x00\x20",
        }
    )
    assert blocked is True
    assert malware_family.upper() in reason


def test_inet_diag_uid_and_inode_are_read_from_64_and_68_byte_offsets():
    payload = bytearray(72)
    struct.pack_into("BBBB", payload, 0, socket.AF_INET, 1, 0, 0)
    struct.pack_into("!HH", payload, 4, 54321, 443)
    payload[8:12] = socket.inet_aton("192.0.2.10")
    payload[24:28] = socket.inet_aton("198.51.100.20")
    struct.pack_into("IIIII", payload, 52, 11, 22, 33, 1001, 987654)

    parsed = NetlinkParser().parse_inet_diag_msg(bytes(payload))

    assert parsed is not None
    assert parsed.src_port == 54321
    assert parsed.dst_port == 443
    assert parsed.uid == 1001
    assert parsed.inode == 987654


def test_feature_extraction_preserves_dns_flow_and_tls_signals():
    extractor = FeatureExtractor()
    features = extractor.extract_features(
        {
            "uid": "client-1",
            "src_ip": "10.0.0.2",
            "src_port": 50000,
            "dst_ip": "203.0.113.9",
            "dst_port": 443,
            "protocol": "TCP",
        },
        tls_metadata={
            "sni": "secure7.example.com",
            "ja3": "example-ja3",
            "tls_version": "TLS 1.3",
            "cipher_count": 12,
            "extension_count": 8,
        },
    )
    named = dict(zip(extractor.get_feature_names(), features, strict=True))

    assert named["dns_length"] > 0
    assert named["dns_entropy"] > 0
    assert named["flow_ip_sum"] > 0
    assert named["flow_dst_port"] == 443
    assert named["flow_is_tcp"] == 1
    assert named["flow_tx_rx_ratio"] > 0
    assert named["tls_has_ja3"] == 1
    assert named["tls_version"] == pytest.approx(1.3)
    assert named["tls_cipher_count"] == 12
    assert named["tls_extension_count"] == 8
    assert named["tls_has_sni"] == 1


def test_isolation_forest_uses_correct_flow_feature_indices(tmp_path):
    detector = IsolationForestDetector(model_path=str(tmp_path / "missing.pkl"))

    assert detector.key_features == [2, 4, 6, 7, 14, 15, 16, 20, 36, 41]

    features = [0.0] * 42
    features[16] = 0.95
    result = detector._rule_based_predict(features)
    assert result["risk_score"] == pytest.approx(0.25)
    assert result["reasons"] == ["exfiltration_pattern"]

    features[16] = 0.0
    features[15] = 0.95
    assert "exfiltration_pattern" not in detector._rule_based_predict(features)["reasons"]


def test_normal_samples_round_trip_current_feature_schema(tmp_path):
    db = ReputationDB(str(tmp_path / "reputation.sqlite3"))
    features = [float(index) for index in range(42)]

    sample_id = db.add_normal_traffic_sample(
        features, client_ip="10.0.0.9", sni="example.com"
    )

    assert sample_id == 1
    assert db.count_normal_traffic_samples() == 1
    assert db.get_normal_traffic_samples() == [features]


def test_normal_sample_rejects_wrong_feature_count(tmp_path):
    db = ReputationDB(str(tmp_path / "reputation.sqlite3"))

    with pytest.raises(ValueError, match="42 finite values"):
        db.add_normal_traffic_sample([0.0] * 41)


def test_isolation_forest_artifact_round_trip(tmp_path):
    model_path = tmp_path / "isolation_forest.pkl"
    samples = [[float((row + column) % 7) for column in range(42)] for row in range(100)]
    detector = IsolationForestDetector(model_path=str(model_path))

    detector.train(samples)
    loaded = IsolationForestDetector(model_path=str(model_path))

    assert model_path.exists()
    assert loaded.is_trained is True
    assert loaded.training_samples == 100
    assert loaded.predict(samples[0])["model"] == "isolation_forest"


def test_reputation_first_strike_upserts_without_profile_update_double_count(tmp_path):
    db = ReputationDB(str(tmp_path / "reputation.sqlite3"))

    assert db.add_strike("new-client") == 1
    db.update_app_reputation("new-client", "client:new-client", 0.7, "WARN")

    reputation = db.get_app_reputation("new-client")
    assert reputation["strike_count"] == 1
    assert reputation["total_connections"] == 1


@pytest.mark.parametrize(
    ("method", "uid", "enabled_field", "disabled_field"),
    [
        ("set_user_trust", "trusted-client", "user_trusted", "user_blocked"),
        ("set_user_block", "blocked-client", "user_blocked", "user_trusted"),
    ],
)
def test_reputation_override_upserts_unseen_uid(
    tmp_path, method, uid, enabled_field, disabled_field
):
    db = ReputationDB(str(tmp_path / "reputation.sqlite3"))

    getattr(db, method)(uid, True)

    reputation = db.get_app_reputation(uid)
    assert reputation is not None
    assert reputation[enabled_field] == 1
    assert reputation[disabled_field] == 0


def test_dashboard_failure_does_not_change_block_decision():
    guard = NetGuard.__new__(NetGuard)
    guard.logger = SimpleNamespace(
        error=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
    )
    guard.db = SimpleNamespace(
        is_ip_blocked=lambda ip: False,
        is_domain_blocked=lambda domain: False,
    )
    guard.enforcer = SimpleNamespace(
        is_client_blocked=lambda client_ip: False,
    )
    guard.extractor = SimpleNamespace(
        extract_features=lambda *args, **kwargs: [0.0] * 42,
        get_feature_names=lambda: [f"feature_{index}" for index in range(42)],
    )
    verdict = {"risk_score": 0.99, "classification": "MALWARE"}
    guard.ai_engine = SimpleNamespace(analyze=lambda *args, **kwargs: verdict)
    guard.url_reputation = SimpleNamespace(check_domain=lambda domain: None)
    guard.decision_engine = SimpleNamespace(
        evaluate_verdict=lambda **kwargs: ("BLOCK", "critical test threat")
    )
    guard.dashboard = SimpleNamespace(
        emit_verdict=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
    )

    result = guard._check_connection(
        {
            "client_ip": "10.0.0.9",
            "client_port": 54321,
            "dst_ip": "203.0.113.9",
            "dst_port": 443,
            "protocol": "TCP",
            "sni": "malware.example",
        }
    )

    assert result == (True, "critical test threat")
