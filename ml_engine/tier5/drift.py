"""Rolling inference telemetry and statistical drift checks.

No raw URLs are stored here. The monitor records the 41 numeric URL features,
probabilities, and predicted class so distribution changes can be detected
without retaining user query strings or credentials.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime

import numpy as np
from scipy.spatial.distance import jensenshannon
from scipy.stats import ks_2samp

import config


class DriftMonitor:
    def __init__(
        self,
        path: str | None = None,
        *,
        baseline_window: int | None = None,
        check_window: int | None = None,
    ):
        self.path = path or config.DRIFT_DB
        self.baseline_window = baseline_window or config.DRIFT_BASELINE_WINDOW
        self.check_window = check_window or config.DRIFT_CHECK_WINDOW
        if self.baseline_window < 2 or self.check_window < 2:
            raise ValueError("drift windows must each contain at least two samples")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    predicted_label TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    features_json TEXT NOT NULL,
                    probabilities_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_predictions_created_at
                    ON predictions(created_at);
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def record(
        self,
        *,
        scan_id: str,
        predicted_label: str,
        risk_score: float,
        features: list[float],
        probabilities: dict[str, float],
    ) -> None:
        if predicted_label not in config.THREAT_CLASSES:
            raise ValueError("invalid predicted label")
        if len(features) != config.MODEL_CONFIG["num_features"]:
            raise ValueError("feature vector does not match model contract")
        if set(probabilities) != set(config.THREAT_CLASSES):
            raise ValueError("probabilities do not match class contract")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO predictions(
                    scan_id, created_at, predicted_label, risk_score,
                    features_json, probabilities_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    datetime.now(UTC).isoformat(),
                    predicted_label,
                    float(risk_score),
                    json.dumps(
                        [float(value) for value in features], separators=(",", ":")
                    ),
                    json.dumps(probabilities, sort_keys=True, separators=(",", ":")),
                ),
            )
            max_rows = int(getattr(config, "DRIFT_MAX_ROWS", 50_000))
            connection.execute(
                """
                DELETE FROM predictions WHERE id IN (
                    SELECT id FROM predictions ORDER BY id DESC LIMIT -1 OFFSET ?
                )
                """,
                (max_rows,),
            )

    def _recent_rows(self) -> list[sqlite3.Row]:
        count = self.baseline_window + self.check_window
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM predictions ORDER BY id DESC LIMIT ?", (count,)
            ).fetchall()
        return list(reversed(rows))

    @staticmethod
    def _class_distribution(rows: list[sqlite3.Row]) -> np.ndarray:
        counts = np.full(len(config.THREAT_CLASSES), 1e-6, dtype=np.float64)
        indexes = {name: index for index, name in enumerate(config.THREAT_CLASSES)}
        for row in rows:
            counts[indexes[row["predicted_label"]]] += 1.0
        return counts / counts.sum()

    def report(self) -> dict:
        rows = self._recent_rows()
        required = self.baseline_window + self.check_window
        if len(rows) < required:
            return {
                "status": "insufficient_data",
                "samples_available": len(rows),
                "samples_required": required,
                "drift_detected": False,
            }

        baseline = rows[: self.baseline_window]
        current = rows[-self.check_window :]
        baseline_features = np.asarray(
            [json.loads(row["features_json"]) for row in baseline]
        )
        current_features = np.asarray(
            [json.loads(row["features_json"]) for row in current]
        )

        feature_alerts = []
        alpha = float(config.DRIFT_KS_ALPHA)
        min_effect = float(getattr(config, "DRIFT_KS_MIN_STATISTIC", 0.2))
        for index in range(config.MODEL_CONFIG["num_features"]):
            statistic, pvalue = ks_2samp(
                baseline_features[:, index], current_features[:, index], method="auto"
            )
            if float(pvalue) < alpha and float(statistic) >= min_effect:
                feature_alerts.append(
                    {
                        "feature_index": index,
                        "ks_statistic": float(statistic),
                        "p_value": float(pvalue),
                    }
                )

        baseline_distribution = self._class_distribution(baseline)
        current_distribution = self._class_distribution(current)
        class_js_distance = float(
            jensenshannon(baseline_distribution, current_distribution, base=2.0)
        )
        baseline_risk = float(np.mean([row["risk_score"] for row in baseline]))
        current_risk = float(np.mean([row["risk_score"] for row in current]))
        risk_shift = current_risk - baseline_risk

        js_threshold = float(getattr(config, "DRIFT_JS_THRESHOLD", 0.15))
        risk_threshold = float(getattr(config, "DRIFT_RISK_SHIFT_THRESHOLD", 0.15))
        drift_detected = bool(
            feature_alerts
            or class_js_distance >= js_threshold
            or abs(risk_shift) >= risk_threshold
        )
        return {
            "status": "alert" if drift_detected else "stable",
            "drift_detected": drift_detected,
            "baseline_samples": len(baseline),
            "current_samples": len(current),
            "feature_alerts": feature_alerts,
            "class_distribution_js_distance": class_js_distance,
            "baseline_mean_risk": baseline_risk,
            "current_mean_risk": current_risk,
            "mean_risk_shift": risk_shift,
            "baseline_class_distribution": dict(
                zip(config.THREAT_CLASSES, baseline_distribution.tolist())
            ),
            "current_class_distribution": dict(
                zip(config.THREAT_CLASSES, current_distribution.tolist())
            ),
        }
