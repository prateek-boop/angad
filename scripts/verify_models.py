"""Fail fast when a bundled ShieldNet or NetGuard model violates its contract."""

from __future__ import annotations

import json
import math

import config
from ml_engine.model import ThreatDetectionModel
from netguard.ai_engine import AIEngine


def main() -> None:
    url_model = ThreatDetectionModel.load(config.MODEL_PATH)
    url_model.warmup()

    engine = AIEngine()
    stats = engine.get_stats()
    if not stats["model_stack_ready"]:
        raise RuntimeError(f"NetGuard model stack is incomplete: {stats}")

    for key in ("payload_classifier", "deep_payload_classifier"):
        metadata = stats[key]
        metrics = metadata["metrics"]
        if metadata["training_samples"] < 100:
            raise RuntimeError(f"{key} has too few training samples")
        for metric in ("balanced_accuracy", "benign_recall", "attack_recall"):
            value = float(metrics.get(metric, math.nan))
            if not math.isfinite(value) or value < 0.8 or value > 1.0:
                raise RuntimeError(f"{key} has invalid {metric}: {value}")
        test_counts = metrics.get("test_class_counts", {})
        if min(int(test_counts.get("benign", 0)), int(test_counts.get("attack", 0))) < 25:
            raise RuntimeError(f"{key} validation set is too small: {test_counts}")

    sample = engine._blend_payload_classifier(
        {
            "risk_score": 0.1,
            "classification": "NORMAL",
            "confidence": 0.5,
            "reasons": [],
        },
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    probabilities = sample.get("payload_model_probabilities", {})
    if set(probabilities) != {"random_forest", "deep"} or not all(
        math.isfinite(value) and 0.0 <= value <= 1.0
        for value in probabilities.values()
    ):
        raise RuntimeError(f"payload inference smoke test failed: {probabilities}")

    print(
        json.dumps(
            {
                "shieldnet_url_model": "ready",
                "netguard_model_stack": "ready",
                "payload_metrics": stats["payload_classifier"]["metrics"],
                "keras_payload_metrics": stats["deep_payload_classifier"]["metrics"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
