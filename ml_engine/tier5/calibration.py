"""Post-hoc temperature scaling for ShieldNet probability outputs.

The Keras artifact exposes probabilities rather than logits. Taking log(p)
recovers logits up to an additive constant, which is sufficient for scalar
temperature scaling. Missing calibration artifacts intentionally degrade to
the identity transform instead of making inference unavailable.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize_scalar

import config

_EPSILON = 1e-7
_SCHEMA_VERSION = 1


def _as_probability_matrix(probabilities) -> np.ndarray:
    matrix = np.asarray(probabilities, dtype=np.float64)
    if matrix.ndim == 1:
        matrix = matrix[None, :]
    if matrix.ndim != 2 or matrix.shape[1] != len(config.THREAT_CLASSES):
        raise ValueError(
            f"expected probabilities with shape (n, {len(config.THREAT_CLASSES)})"
        )
    if not np.all(np.isfinite(matrix)) or np.any(matrix < 0):
        raise ValueError("probabilities must be finite and non-negative")
    row_sums = matrix.sum(axis=1, keepdims=True)
    if np.any(row_sums <= 0):
        raise ValueError("each probability row must have positive mass")
    return matrix / row_sums


@dataclass(slots=True)
class TemperatureCalibrator:
    temperature: float = 1.0
    fitted_samples: int = 0

    def transform(self, probabilities) -> np.ndarray:
        matrix = _as_probability_matrix(probabilities)
        temperature = float(self.temperature)
        if not np.isfinite(temperature) or temperature <= 0:
            raise ValueError("temperature must be a positive finite number")

        scaled_logits = np.log(np.clip(matrix, _EPSILON, 1.0)) / temperature
        scaled_logits -= scaled_logits.max(axis=1, keepdims=True)
        exp_logits = np.exp(scaled_logits)
        return exp_logits / exp_logits.sum(axis=1, keepdims=True)

    def fit(self, probabilities, labels) -> TemperatureCalibrator:
        matrix = _as_probability_matrix(probabilities)
        y = np.asarray(labels, dtype=np.int64)
        if y.ndim != 1 or len(y) != len(matrix):
            raise ValueError("labels must contain one class index per probability row")
        if len(y) < 2 or np.any(y < 0) or np.any(y >= matrix.shape[1]):
            raise ValueError("labels contain invalid class indices")

        log_probs = np.log(np.clip(matrix, _EPSILON, 1.0))

        def negative_log_likelihood(log_temperature: float) -> float:
            temperature = float(np.exp(log_temperature))
            logits = log_probs / temperature
            logits -= logits.max(axis=1, keepdims=True)
            calibrated = np.exp(logits)
            calibrated /= calibrated.sum(axis=1, keepdims=True)
            return float(
                -np.log(np.clip(calibrated[np.arange(len(y)), y], _EPSILON, 1.0)).mean()
            )

        result = minimize_scalar(
            negative_log_likelihood,
            bounds=(float(np.log(0.05)), float(np.log(20.0))),
            method="bounded",
        )
        if not result.success:
            raise RuntimeError(f"temperature fitting failed: {result.message}")

        self.temperature = float(np.exp(result.x))
        self.fitted_samples = int(len(y))
        return self

    def to_dict(self) -> dict:
        return {
            "schema_version": _SCHEMA_VERSION,
            "classes": list(config.THREAT_CLASSES),
            "method": "temperature_scaling",
            "temperature": self.temperature,
            "fitted_samples": self.fitted_samples,
        }

    def save(self, path: str | None = None) -> None:
        path = path or config.CALIBRATION_PATH
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".calibration-", suffix=".json", dir=directory
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.to_dict(), handle, indent=2)
                handle.write("\n")
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    @classmethod
    def load(cls, path: str | None = None) -> TemperatureCalibrator:
        path = path or config.CALIBRATION_PATH
        if not os.path.exists(path):
            return cls()
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        if payload.get("schema_version") != _SCHEMA_VERSION:
            raise ValueError("unsupported calibration artifact schema")
        if payload.get("classes") != config.THREAT_CLASSES:
            raise ValueError("calibration class order does not match model contract")
        return cls(
            temperature=float(payload["temperature"]),
            fitted_samples=int(payload.get("fitted_samples", 0)),
        )
