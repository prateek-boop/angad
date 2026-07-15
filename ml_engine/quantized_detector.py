"""Runtime inference against the quantized TFLite model — for lightweight
deployment paths that don't want a full TensorFlow/Keras load. See
MODEL_BRAIN.md sec 11."""

import json
import os
import threading

import numpy as np
import tensorflow as tf

import config
from ml_engine.feature_extractor import FeatureExtractor
from ml_engine.quantize_model import calibration_snapshot_path
from ml_engine.tier5.calibration import TemperatureCalibrator
from ml_engine.url_tokenizer import URLTokenizer

_TEMPERATURE_TOLERANCE = 1e-9


class CalibrationDriftError(RuntimeError):
    """The tflite export and the live calibration artifact disagree."""


class QuantizedThreatDetector:
    def __init__(self, tflite_path: str = config.TFLITE_MODEL_PATH):
        if not os.path.isfile(tflite_path):
            raise FileNotFoundError(
                f"quantized model not found at {tflite_path}; run `shieldnet quantize`"
            )
        self.interpreter = tf.lite.Interpreter(model_path=tflite_path)
        self.interpreter.allocate_tensors()
        self._input_details = self.interpreter.get_input_details()
        self._output_details = self.interpreter.get_output_details()[0]
        self.tokenizer = URLTokenizer()
        self.extractor = FeatureExtractor()
        self.calibrator = TemperatureCalibrator.load(config.CALIBRATION_PATH)
        self._verify_calibration_consistency(tflite_path)
        self._lock = threading.Lock()

    def _verify_calibration_consistency(self, tflite_path: str) -> None:
        snapshot_path = calibration_snapshot_path(tflite_path)
        if not os.path.isfile(snapshot_path):
            return
        with open(snapshot_path, encoding="utf-8") as f:
            snapshot = json.load(f)
        exported_temperature = float(snapshot.get("temperature", 1.0))
        if abs(exported_temperature - self.calibrator.temperature) > _TEMPERATURE_TOLERANCE:
            raise CalibrationDriftError(
                "quantized model and calibration artifact are out of sync: "
                f"tflite was exported with temperature={exported_temperature}, "
                f"current calibration.json has temperature={self.calibrator.temperature}. "
                "Rerun `shieldnet quantize` after retraining, or restore the "
                "matching calibration.json."
            )

    def predict(self, url: str) -> dict:
        url_ids = self.tokenizer.encode_batch([url])
        features = np.array([self.extractor.extract(url)], dtype=np.float32)

        with self._lock:
            for detail in self._input_details:
                if "url_input" in detail["name"]:
                    self.interpreter.set_tensor(detail["index"], url_ids)
                else:
                    self.interpreter.set_tensor(detail["index"], features)
            self.interpreter.invoke()
            raw_probs = self.interpreter.get_tensor(self._output_details["index"])[0]

        probs = self.calibrator.transform([raw_probs])[0]
        idx = int(np.argmax(probs))
        return {
            "category": config.THREAT_CLASSES[idx],
            "confidence": float(probs[idx]),
            "probabilities": {
                cls: float(p) for cls, p in zip(config.THREAT_CLASSES, probs)
            },
        }


if __name__ == "__main__":
    import sys

    detector = QuantizedThreatDetector()
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.google.com"
    print(detector.predict(url))
