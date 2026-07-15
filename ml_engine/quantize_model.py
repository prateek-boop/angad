"""Converts the trained Keras model to a dynamic-range-quantized TFLite model
for lightweight CPU inference. See MODEL_BRAIN.md sec 11."""

import numpy as np
import tensorflow as tf
import os
import tempfile

import config
from ml_engine.feature_extractor import FeatureExtractor
from ml_engine.url_tokenizer import URLTokenizer


def quantize(
    keras_model_path: str = config.MODEL_PATH, out_path: str = config.TFLITE_MODEL_PATH
) -> str:
    model = tf.keras.models.load_model(keras_model_path)

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()

    directory = os.path.dirname(out_path) or "."
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=directory, prefix=".shieldnet-", suffix=".tflite"
    )
    try:
        with os.fdopen(descriptor, "wb") as f:
            f.write(tflite_model)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, out_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return out_path


def sanity_check(
    keras_model_path: str = config.MODEL_PATH,
    tflite_path: str = config.TFLITE_MODEL_PATH,
    sample_urls: list[str] | None = None,
) -> float:
    """Compares float vs quantized predictions on a held-out sample, returns
    mean absolute probability difference."""
    sample_urls = sample_urls or [
        "https://www.google.com/search?q=test",
        "http://paypal-verify.suspicious-domain.xyz/login",
        "http://192.168.1.1/setup.exe",
    ]

    tokenizer = URLTokenizer()
    extractor = FeatureExtractor()
    url_ids = tokenizer.encode_batch(sample_urls)
    features = np.array([extractor.extract(u) for u in sample_urls], dtype=np.float32)

    keras_model = tf.keras.models.load_model(keras_model_path)
    float_probs = keras_model.predict(
        {"url_input": url_ids, "feature_input": features}, verbose=0
    )

    interpreter = tf.lite.Interpreter(model_path=tflite_path)
    interpreter.allocate_tensors()
    output_details = interpreter.get_output_details()[0]

    quant_probs = []
    for i in range(len(sample_urls)):
        for detail in interpreter.get_input_details():
            if "url_input" in detail["name"]:
                interpreter.set_tensor(detail["index"], url_ids[i : i + 1])
            else:
                interpreter.set_tensor(detail["index"], features[i : i + 1])
        interpreter.invoke()
        quant_probs.append(interpreter.get_tensor(output_details["index"])[0])
    quant_probs = np.array(quant_probs)

    return float(np.mean(np.abs(float_probs - quant_probs)))


if __name__ == "__main__":
    path = quantize()
    print(f"Saved quantized model to {path}")
    diff = sanity_check()
    print(f"Mean abs probability difference (float vs quantized): {diff:.6f}")
