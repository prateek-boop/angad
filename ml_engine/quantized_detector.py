"""Runtime inference against the quantized TFLite model — for lightweight
deployment paths that don't want a full TensorFlow/Keras load. See
MODEL_BRAIN.md sec 11."""

import numpy as np
import tensorflow as tf
import os
import threading

import config
from ml_engine.feature_extractor import FeatureExtractor
from ml_engine.url_tokenizer import URLTokenizer
from ml_engine.tier5.calibration import TemperatureCalibrator


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
        self._lock = threading.Lock()

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
