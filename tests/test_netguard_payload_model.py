import logging
import os
import pickle
import random
import socket
import struct
from pathlib import Path

import pytest
from sklearn.ensemble import RandomForestClassifier

from netguard.ai_engine import AIEngine
from netguard.payload_model import (
    MAX_PAYLOAD_BYTES,
    PAYLOAD_ARTIFACT_FORMAT,
    PAYLOAD_SCHEMA,
    extract_iot23_samples,
    extract_payload_features,
    train_iot23_payload_model,
)

MODEL_PATH = (
    Path(__file__).resolve().parents[1] / "netguard" / "models" / "payload_classifier.pkl"
)


def _build_frame(src_ip, dst_ip, src_port, dst_port, payload):
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ip_header = bytearray(20)
    ip_header[0] = 0x45
    struct.pack_into("!H", ip_header, 2, 40 + len(payload))
    ip_header[8] = 64
    ip_header[9] = socket.IPPROTO_TCP
    ip_header[12:16] = socket.inet_aton(src_ip)
    ip_header[16:20] = socket.inet_aton(dst_ip)
    tcp_header = bytearray(20)
    struct.pack_into("!HHII", tcp_header, 0, src_port, dst_port, 1000, 0)
    tcp_header[12] = 0x50
    tcp_header[13] = 0x18
    tcp_header[14:16] = struct.pack("!H", 65535)
    return bytes(eth) + bytes(ip_header) + bytes(tcp_header) + payload


def _write_pcap(path, packets):
    with open(path, "wb") as file:
        file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, src_port, dst_port, payload in packets:
            seconds = int(ts)
            micros = int(round((ts - seconds) * 1_000_000))
            frame = _build_frame("10.0.0.10", "192.168.1.10", src_port, dst_port, payload)
            file.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            file.write(frame)


def _write_labels(path, lines):
    with open(path, "w", encoding="utf-8") as file:
        file.write("#separator \x09\n")
        file.write(
            "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service "
            "duration orig_bytes resp_bytes conn_state local_orig local_resp "
            "missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes "
            "tunnel_parents label detailed-label\n"
        )
        file.write("\n".join(lines) + "\n")


def _make_capture(tmp_path, name, base_ts, seed, count_per_class):
    rng = random.Random(seed)
    packets = []
    lines = []
    for index in range(count_per_class):
        src_port = 10000 + index
        dst_port = 8000 + index
        ts = base_ts + index * 2
        label_ts = ts - 1.0
        if index % 2 == 0:
            payload = (
                f"GET /page{index} HTTP/1.1\r\n"
                f"Host: example.com\r\nUser-Agent: curl/7.68\r\n\r\n"
            ).encode()
            label = "benign"
        else:
            payload = bytes(rng.randrange(256) for _ in range(40 + index % 200))
            label = "Malicious"
        packets.append((ts, src_port, dst_port, payload))
        lines.append(
            f"{label_ts} C{seed}-{index} 10.0.0.10 {src_port} 192.168.1.10 {dst_port} "
            f"tcp - 0.5 {len(payload)} {len(payload)} SF - - 0 S 1 {40 + len(payload)} "
            f"1 40 - {label} Attack/Scan"
        )
    pcap = tmp_path / f"{name}.pcap"
    labels = tmp_path / f"{name}.conn.log.labeled"
    _write_pcap(pcap, packets)
    _write_labels(labels, lines)
    return pcap, labels


def test_payload_features_are_causal_and_deterministic():
    payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    first = extract_payload_features(payload)
    second = extract_payload_features(payload)
    random_payload = extract_payload_features(os.urandom(128))

    assert first == second
    assert len(first) == 266
    assert first[4] == 0.0  # not a TLS ClientHello
    assert first[5] == 1.0  # HTTP request marker
    assert first[6] == 1.0  # contains CRLF
    assert first != random_payload


def test_payload_training_round_trip_with_unseen_capture_holdout(tmp_path):
    capture_a = _make_capture(tmp_path, "a", 100000, seed=1, count_per_class=120)
    capture_b = _make_capture(tmp_path, "b", 200000, seed=2, count_per_class=120)
    output = tmp_path / "payload_classifier.pkl"

    result = train_iot23_payload_model([capture_a, capture_b], str(output))

    assert output.exists()
    assert result["benign_recall"] >= 0.8
    assert result["attack_recall"] >= 0.8
    assert result["balanced_accuracy"] >= 0.8

    with output.open("rb") as file:
        artifact = pickle.load(file)
    assert artifact["feature_schema"] == PAYLOAD_SCHEMA
    assert list(artifact["model"].classes_) == [0, 1]
    assert artifact["training_samples"] > 0
    assert artifact["class_counts"]["benign"] == 120
    assert artifact["class_counts"]["attack"] == 120
    assert artifact["dataset"]["validation_scope"] == "complete_unseen_capture"
    assert artifact["metrics"]["test_class_counts"] == {"benign": 60, "attack": 60}
    assert len(artifact["dataset"]["captures"]) == 2


def test_payload_extraction_joins_labels_from_multiple_captures(tmp_path):
    capture_a = _make_capture(tmp_path, "a", 100000, seed=1, count_per_class=30)
    capture_b = _make_capture(tmp_path, "b", 200000, seed=2, count_per_class=30)

    X, y, groups = extract_iot23_samples([capture_a, capture_b])

    assert X.shape[0] == 60
    assert y.shape[0] == 60
    assert len(set(groups.tolist())) == 2
    assert set(y.tolist()) == {0, 1}


def test_payload_training_rejects_insufficient_class_samples(tmp_path):
    capture = _make_capture(tmp_path, "small", 100000, seed=3, count_per_class=50)

    with pytest.raises(ValueError, match="at least 100 payload samples per class"):
        train_iot23_payload_model([capture], str(tmp_path / "out.pkl"))


def test_ai_engine_loads_payload_classifier_and_rejects_bad_artifact(tmp_path, caplog):
    real_bytes = MODEL_PATH.read_bytes() if MODEL_PATH.exists() else None
    engine = AIEngine.__new__(AIEngine)
    engine.logger = logging.getLogger("test.payload_engine")
    engine.payload_classifier = None
    engine.payload_model_metadata = {}

    def _write_artifact(payload):
        with MODEL_PATH.open("wb") as file:
            pickle.dump(payload, file)

    try:
        _write_artifact(
            {
                "artifact_format": PAYLOAD_ARTIFACT_FORMAT,
                "feature_schema": "wrong-schema",
                "max_payload_bytes": MAX_PAYLOAD_BYTES,
                "class_names": ["benign", "attack"],
                "model": object(),
            }
        )
        engine._load_payload_classifier()
        assert engine.payload_classifier is None
        assert "schema mismatch" in caplog.text

        tiny_model = RandomForestClassifier(n_estimators=2, random_state=0)
        tiny_model.fit([[0, 1], [1, 0]], [0, 1])
        _write_artifact(
            {
                "artifact_format": PAYLOAD_ARTIFACT_FORMAT,
                "feature_schema": PAYLOAD_SCHEMA,
                "max_payload_bytes": MAX_PAYLOAD_BYTES,
                "class_names": ["benign", "attack"],
                "model": tiny_model,
                "training_samples": 2,
            }
        )
        engine._load_payload_classifier()
        assert engine.payload_classifier is None
        assert "feature count mismatch" in caplog.text

        if real_bytes is not None:
            MODEL_PATH.write_bytes(real_bytes)
            engine._load_payload_classifier()
            assert engine.payload_classifier is not None
            assert engine.payload_model_metadata["training_samples"] > 0
    finally:
        if real_bytes is not None:
            MODEL_PATH.write_bytes(real_bytes)
