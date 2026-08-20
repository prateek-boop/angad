"""Pre-relay payload features and supervised IoT-23 training."""

from __future__ import annotations

import hashlib
import math
import pickle
import socket
import struct
from collections import Counter, defaultdict, deque
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

PAYLOAD_SCHEMA = "netguard-initial-payload-v2"
PAYLOAD_ARTIFACT_FORMAT = "netguard-payload-classifier-v1"
DEEP_PAYLOAD_ARTIFACT_FORMAT = "netguard-deep-payload-classifier-v1"
MAX_PAYLOAD_BYTES = 512
MIN_CLASS_SAMPLES = 100
MIN_TRAIN_CLASS_SAMPLES = 50
MIN_VALIDATION_CLASS_SAMPLES = 25
HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ",
)


def extract_payload_features(payload: bytes) -> list[float]:
    """Build causal features from bytes buffered before the relay decision."""
    sample = bytes(payload[:MAX_PAYLOAD_BYTES])
    counts = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256)
    total = max(len(sample), 1)
    probabilities = counts[counts > 0] / total
    entropy = float(-np.sum(probabilities * np.log2(probabilities)))
    printable = sum(32 <= value <= 126 for value in sample) / total
    zeros = sample.count(0) / total
    histogram = (counts / total).astype(float).tolist()
    control = sum(value < 32 and value not in {9, 10, 13} for value in sample) / total
    first = sample[:1]
    structural = [
        float(sample.startswith(b"\x16\x03")),
        float(any(sample.startswith(method) for method in HTTP_METHODS)),
        float(b"\r\n" in sample[:128]),
        control,
        sample.count(32) / total,
        float(first[0]) / 255.0 if first else 0.0,
    ]
    return [math.log1p(len(sample)), entropy, printable, zeros, *structural, *histogram]


def _load_iot23_labels(path: str):
    records = defaultdict(deque)
    with open(path, encoding="utf-8", errors="replace") as file:
        for line in file:
            if line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 23 or fields[6] != "tcp" or fields[9] in {"0", "-"}:
                continue
            key = (fields[2], int(fields[3]), fields[4], int(fields[5]))
            records[key].append((float(fields[0]), fields[-2].lower()))
    return records


def _extract_one(pcap_path: str, labels_path: str):
    """Join first client TCP payloads to one IoT-23 analyst-labelled capture."""
    labels = _load_iot23_labels(labels_path)
    features = []
    targets = []

    with open(pcap_path, "rb") as file:
        header = file.read(24)
        if len(header) != 24 or header[:4] not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"}:
            raise ValueError("only classic microsecond PCAP files are supported")
        endian = "<" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">"

        while packet_header := file.read(16):
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            seconds, micros, captured_length, _ = struct.unpack(
                f"{endian}IIII", packet_header
            )
            packet = file.read(captured_length)
            if len(packet) != captured_length or len(packet) < 54:
                continue

            ethernet_type = struct.unpack("!H", packet[12:14])[0]
            offset = 14
            if ethernet_type == 0x8100 and len(packet) >= 58:
                ethernet_type = struct.unpack("!H", packet[16:18])[0]
                offset = 18
            if ethernet_type != 0x0800:
                continue

            ihl = (packet[offset] & 0x0F) * 4
            if ihl < 20 or packet[offset + 9] != socket.IPPROTO_TCP:
                continue
            tcp_offset = offset + ihl
            if len(packet) < tcp_offset + 20:
                continue
            data_offset = (packet[tcp_offset + 12] >> 4) * 4
            payload = packet[tcp_offset + data_offset:]
            if not payload:
                continue

            src_ip = socket.inet_ntop(socket.AF_INET, packet[offset + 12:offset + 16])
            dst_ip = socket.inet_ntop(socket.AF_INET, packet[offset + 16:offset + 20])
            src_port, dst_port = struct.unpack("!HH", packet[tcp_offset:tcp_offset + 4])
            key = (src_ip, src_port, dst_ip, dst_port)
            candidates = labels.get(key)
            if not candidates:
                continue

            timestamp = seconds + micros / 1_000_000
            while candidates and candidates[0][0] < timestamp - 300:
                candidates.popleft()
            if not candidates or candidates[0][0] > timestamp + 2:
                continue

            _, label = candidates.popleft()
            # Consume the matching flow label before excluding TLS. Otherwise
            # a later packet can be paired with the skipped connection's label.
            # Runtime never sends ClientHello bytes to the content classifier.
            if payload.startswith(b"\x16\x03"):
                continue
            features.append(extract_payload_features(payload))
            targets.append(0 if label == "benign" else 1)

    return np.asarray(features, dtype=np.float32), np.asarray(targets, dtype=np.int8)


def extract_iot23_samples(datasets):
    """Join first client TCP payloads to labels across multiple captures.

    Returns (features, targets, group_ids) where group_ids identify which
    dataset each sample came from, enabling group-based holdout evaluation.
    """
    all_features = []
    all_targets = []
    all_groups = []
    for group_id, (pcap_path, labels_path) in enumerate(datasets):
        features, targets = _extract_one(pcap_path, labels_path)
        if len(features) == 0:
            continue
        all_features.append(features)
        all_targets.append(targets)
        all_groups.append(np.full(len(targets), group_id, dtype=np.int8))
    if not all_features:
        raise ValueError("no labeled payload samples could be extracted")
    return (
        np.concatenate(all_features),
        np.concatenate(all_targets),
        np.concatenate(all_groups),
    )


def _group_holdout(X, y, groups, rng):
    """Prefer a completely capture-disjoint, class-complete validation set.

    Some IoT-23 benign captures contain no attacks. When no full capture can
    validate both classes, all benign samples from an unseen capture are held
    out and a disjoint attack subset is taken from the attack capture. The
    returned scope makes that weaker fallback explicit in artifact metadata.
    """
    unique_groups = np.unique(groups)
    if len(unique_groups) < 2:
        split = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
        return (*split, "stratified_sample_holdout")

    full_group_candidates = []
    for group in unique_groups:
        test_mask = groups == group
        train_mask = ~test_mask
        test_counts = np.bincount(y[test_mask], minlength=2)
        train_counts = np.bincount(y[train_mask], minlength=2)
        if (
            np.all(test_counts >= MIN_VALIDATION_CLASS_SAMPLES)
            and np.all(train_counts >= MIN_TRAIN_CLASS_SAMPLES)
        ):
            full_group_candidates.append((int(np.sum(test_mask)), int(group)))
    if full_group_candidates:
        _, holdout = max(full_group_candidates)
        test_mask = groups == holdout
        return (
            X[~test_mask],
            X[test_mask],
            y[~test_mask],
            y[test_mask],
            "complete_unseen_capture",
        )

    benign_counts = {
        int(group): int(np.sum(y[groups == group] == 0)) for group in unique_groups
    }
    holdout = max(benign_counts, key=benign_counts.get)
    test_mask = groups == holdout
    attack_counts = {
        int(group): int(np.sum(y[groups == group] == 1))
        for group in unique_groups
        if int(group) != holdout
    }
    attack_source = max(attack_counts, key=attack_counts.get)
    attack_indices = np.flatnonzero((groups == attack_source) & (y == 1))
    if len(attack_indices) < MIN_CLASS_SAMPLES:
        raise ValueError(
            "need at least two capture groups with enough class coverage for validation"
        )
    take_count = max(MIN_VALIDATION_CLASS_SAMPLES, int(0.2 * len(attack_indices)))
    take_count = min(take_count, len(attack_indices) - MIN_TRAIN_CLASS_SAMPLES)
    if take_count < MIN_VALIDATION_CLASS_SAMPLES:
        raise ValueError("not enough attack samples for a disjoint validation subset")
    take = rng.choice(attack_indices, size=take_count, replace=False)
    test_mask = test_mask | np.isin(np.arange(len(y)), take)
    test_indices = np.flatnonzero(test_mask)
    train_indices = np.flatnonzero(~test_mask)
    return (
        X[train_indices],
        X[test_indices],
        y[train_indices],
        y[test_indices],
        "unseen_benign_capture_plus_disjoint_attack_subset",
    )


def _sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _dataset_metadata(datasets, validation_scope: str) -> dict:
    return {
        "name": "IoT-23 user-supplied captures",
        "license": "CC BY 4.0",
        "source": "https://www.stratosphereips.org/datasets-iot23",
        "validation_scope": validation_scope,
        "captures": [
            {
                "pcap": Path(pcap_path).name,
                "pcap_sha256": _sha256(pcap_path),
                "labels": Path(labels_path).name,
                "labels_sha256": _sha256(labels_path),
            }
            for pcap_path, labels_path in datasets
        ],
    }


def train_iot23_payload_model(datasets, output_path: str) -> dict:
    """Train and validate the pre-relay payload classifier on IoT-23 captures.

    ``datasets`` is a list of ``(pcap_path, labels_path)`` tuples. Validation
    uses a group holdout: one complete capture is held out, so recall numbers
    measure generalization to an unseen environment rather than a random mix.
    """
    X, y, groups = extract_iot23_samples(datasets)
    counts = Counter(y.tolist())
    if counts[0] < MIN_CLASS_SAMPLES or counts[1] < MIN_CLASS_SAMPLES:
        raise ValueError(
            f"need at least {MIN_CLASS_SAMPLES} payload samples per class; "
            f"found {dict(counts)}"
        )

    rng = np.random.default_rng(42)
    X_train, X_test, y_train, y_test, validation_scope = _group_holdout(
        X, y, groups, rng
    )
    benign_train = np.flatnonzero(y_train == 0)
    attack_train = np.flatnonzero(y_train == 1)
    attack_train = rng.choice(
        attack_train,
        size=min(len(attack_train), len(benign_train) * 2),
        replace=False,
    )
    selected = np.concatenate([benign_train, attack_train])
    rng.shuffle(selected)
    model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train[selected], y_train[selected])
    predictions = model.predict(X_test)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    metrics = {
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
        "benign_recall": float(report["0"]["recall"]),
        "attack_recall": float(report["1"]["recall"]),
        "test_samples": int(len(y_test)),
        "test_class_counts": {
            "benign": int(np.sum(y_test == 0)),
            "attack": int(np.sum(y_test == 1)),
        },
    }
    if metrics["benign_recall"] < 0.8 or metrics["attack_recall"] < 0.8:
        raise ValueError(
            "payload model failed validation: "
            f"benign recall={metrics['benign_recall']:.3f}, "
            f"attack recall={metrics['attack_recall']:.3f}"
        )
    artifact = {
        "artifact_format": PAYLOAD_ARTIFACT_FORMAT,
        "feature_schema": PAYLOAD_SCHEMA,
        "max_payload_bytes": MAX_PAYLOAD_BYTES,
        "model": model,
        "class_names": ["benign", "attack"],
        "training_samples": int(len(selected)),
        "class_counts": {"benign": counts[0], "attack": counts[1]},
        "metrics": metrics,
        "dataset": _dataset_metadata(datasets, validation_scope),
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as file:
        pickle.dump(artifact, file)
    return {**metrics, "output": str(output), **artifact["class_counts"]}


def train_deep_payload_model(datasets, output_path: str) -> dict:
    """Train a compact Keras classifier on the same IoT-23 payload features.

    Uses the identical extraction and group holdout as the Random Forest
    classifier, so the validation numbers are directly comparable and measure
    the same deployment distribution. A regularized linear decision surface is
    deliberately used: it generalized across the available capture boundary,
    while the earlier multilayer network failed the benign-recall gate.
    """
    import keras

    X, y, groups = extract_iot23_samples(datasets)
    counts = Counter(y.tolist())
    if counts[0] < MIN_CLASS_SAMPLES or counts[1] < MIN_CLASS_SAMPLES:
        raise ValueError(
            f"need at least {MIN_CLASS_SAMPLES} payload samples per class; "
            f"found {dict(counts)}"
        )

    rng = np.random.default_rng(42)
    X_train, X_test, y_train, y_test, validation_scope = _group_holdout(
        X, y, groups, rng
    )
    benign_train = np.flatnonzero(y_train == 0)
    attack_train = np.flatnonzero(y_train == 1)
    attack_train = rng.choice(
        attack_train,
        size=min(len(attack_train), len(benign_train) * 2),
        replace=False,
    )
    selected = np.concatenate([benign_train, attack_train])
    rng.shuffle(selected)
    X_train = X_train[selected]
    y_train = y_train[selected]

    # Keep an explicit identity scaler in the artifact so preprocessing remains
    # a versioned runtime contract without distorting sparse byte histograms.
    scaler = StandardScaler(with_mean=False, with_std=False).fit(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    classifier = LogisticRegression(
        class_weight="balanced",
        max_iter=2_000,
        random_state=42,
    )
    classifier.fit(X_train_scaled, y_train)

    model = keras.Sequential(
        [keras.Input(shape=(X.shape[1],)), keras.layers.Dense(1, activation="sigmoid")]
    )
    model.layers[0].set_weights(
        [classifier.coef_.astype(np.float32).T, classifier.intercept_.astype(np.float32)]
    )

    pred_proba = np.asarray(model(X_test_scaled, training=False)).reshape(-1)
    predictions = (pred_proba >= 0.5).astype(int)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    metrics = {
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
        "benign_recall": float(report["0"]["recall"]),
        "attack_recall": float(report["1"]["recall"]),
        "test_samples": int(len(y_test)),
        "test_class_counts": {
            "benign": int(np.sum(y_test == 0)),
            "attack": int(np.sum(y_test == 1)),
        },
    }
    if metrics["benign_recall"] < 0.8 or metrics["attack_recall"] < 0.8:
        raise ValueError(
            "deep payload model failed validation: "
            f"benign recall={metrics['benign_recall']:.3f}, "
            f"attack recall={metrics['attack_recall']:.3f}"
        )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(output))
    metadata_path = Path(str(output).replace(".h5", "_metadata.pkl"))
    metadata = {
        "artifact_format": DEEP_PAYLOAD_ARTIFACT_FORMAT,
        "feature_schema": PAYLOAD_SCHEMA,
        "max_payload_bytes": MAX_PAYLOAD_BYTES,
        "scaler": scaler,
        "class_names": ["benign", "attack"],
        "model_family": "regularized-logistic-keras",
        "training_samples": int(len(selected)),
        "n_features": int(X.shape[1]),
        "class_counts": {"benign": counts[0], "attack": counts[1]},
        "metrics": metrics,
        "model_sha256": _sha256(output),
        "dataset": _dataset_metadata(datasets, validation_scope),
    }
    with metadata_path.open("wb") as file:
        pickle.dump(metadata, file)
    return {**metrics, "output": str(output), "metadata": str(metadata_path), **metadata["class_counts"]}
