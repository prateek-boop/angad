"""Dual-branch TensorFlow/Keras threat detection model. See MODEL_BRAIN.md
sec 6: CNN+attention branch over URL char tokens, dense/residual branch over
the 41 engineered features, fusion head -> 5-class softmax."""

import os
import threading

import numpy as np
from tensorflow import keras
from tensorflow.keras import layers

from config import MODEL_CONFIG, THREAT_CLASSES

MODEL_NAME = "ShieldNet_v2_Attention"


def _cnn_attention_branch(url_input: keras.KerasTensor) -> keras.KerasTensor:
    cfg = MODEL_CONFIG
    x = layers.Embedding(
        input_dim=cfg["vocab_size"],
        output_dim=cfg["embedding_dim"],
        name="char_embedding",
    )(url_input)

    conv_outputs = []
    for kernel_size in cfg["conv_kernels"]:
        conv = layers.Conv1D(
            cfg["conv_filters"],
            kernel_size,
            padding="same",
            activation="relu",
            name=f"conv1d_k{kernel_size}",
        )(x)
        conv_outputs.append(conv)
    merged = layers.Concatenate(name="conv_concat")(conv_outputs)
    merged = layers.Conv1D(cfg["conv_filters"], 3, padding="same", activation="relu")(
        merged
    )

    attention = layers.MultiHeadAttention(
        num_heads=4,
        key_dim=cfg["conv_filters"] // 4,
        name="url_self_attention",
    )(merged, merged)
    attended = layers.Add()([merged, attention])
    attended = layers.LayerNormalization()(attended)

    max_pool = layers.GlobalMaxPooling1D()(attended)
    avg_pool = layers.GlobalAveragePooling1D()(attended)
    pooled = layers.Concatenate()([max_pool, avg_pool])

    dense = layers.Dense(128, activation="relu")(pooled)
    dense = layers.Dropout(0.3)(dense)
    return layers.Dense(64, activation="relu", name="cnn_branch_output")(dense)


def _dense_block(x, units: int):
    x = layers.Dense(units, activation="relu")(x)
    x = layers.BatchNormalization()(x)
    return layers.Dropout(0.2)(x)


def _feature_dnn_branch(feature_input: keras.KerasTensor) -> keras.KerasTensor:
    x = layers.BatchNormalization()(feature_input)
    x = _dense_block(x, 128)

    residual_in = layers.Dense(64, activation="relu")(x)
    residual = _dense_block(residual_in, 64)
    x = layers.Add()([residual_in, residual])

    return layers.Dense(64, activation="relu", name="feature_branch_output")(x)


def build_model() -> keras.Model:
    cfg = MODEL_CONFIG

    url_input = keras.Input(
        shape=(cfg["max_url_length"],), dtype="int32", name="url_input"
    )
    feature_input = keras.Input(
        shape=(cfg["num_features"],), dtype="float32", name="feature_input"
    )

    cnn_out = _cnn_attention_branch(url_input)
    feature_out = _feature_dnn_branch(feature_input)

    fused = layers.Concatenate(name="fusion_concat")([cnn_out, feature_out])
    x = layers.Dense(256, activation="relu")(fused)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(128, activation="relu")(x)
    x = layers.Dropout(0.2)(x)
    x = layers.Dense(64, activation="relu")(x)
    logits = layers.Dense(cfg["num_classes"], name="logits")(x)
    probabilities = layers.Activation("softmax", name="probabilities")(logits)

    model = keras.Model(
        inputs={"url_input": url_input, "feature_input": feature_input},
        outputs=probabilities,
        name=MODEL_NAME,
    )
    return model


class ThreatDetectionModel:
    """Thin wrapper around the Keras model providing the runtime contract:
    load a saved model, predict with confidence, return class + all probs."""

    def __init__(self, model: keras.Model | None = None):
        self.model = model or build_model()
        self._prediction_lock = threading.Lock()

    @classmethod
    def load(cls, path: str) -> "ThreatDetectionModel":
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"ShieldNet model not found at {path}; run `python main.py train` first"
            )
        model = keras.models.load_model(path)
        input_shapes = {
            tensor.name.split(":", 1)[0]: tuple(tensor.shape) for tensor in model.inputs
        }
        if input_shapes.get("url_input") != (None, MODEL_CONFIG["max_url_length"]):
            raise ValueError("saved model URL input shape does not match config")
        if input_shapes.get("feature_input") != (None, MODEL_CONFIG["num_features"]):
            raise ValueError("saved model feature input shape does not match config")
        if tuple(model.output_shape) != (None, len(THREAT_CLASSES)):
            raise ValueError("saved model output does not match the class contract")
        return cls(model)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.model.save(path)

    def warmup(self) -> None:
        """Materialize TensorFlow execution state before threaded serving."""
        url_ids = np.zeros((1, MODEL_CONFIG["max_url_length"]), dtype=np.int32)
        features = np.zeros((1, MODEL_CONFIG["num_features"]), dtype=np.float32)
        self.predict_with_confidence(url_ids, features)

    def predict_with_confidence(
        self, url_ids: np.ndarray, features: np.ndarray
    ) -> list[dict]:
        url_ids = np.asarray(url_ids, dtype=np.int32)
        features = np.asarray(features, dtype=np.float32)
        expected_url_shape = (None, MODEL_CONFIG["max_url_length"])
        expected_feature_shape = (None, MODEL_CONFIG["num_features"])
        if url_ids.ndim != 2 or url_ids.shape[1] != expected_url_shape[1]:
            raise ValueError(f"url_ids must have shape {expected_url_shape}")
        if features.ndim != 2 or features.shape[1] != expected_feature_shape[1]:
            raise ValueError(f"features must have shape {expected_feature_shape}")
        if len(url_ids) != len(features):
            raise ValueError("url_ids and features must have the same batch size")
        if not np.all(np.isfinite(features)):
            raise ValueError("features must be finite")

        # Keras model calls avoid predict()'s per-request dataset setup. The
        # lock gives one shared model a stable concurrent FastAPI runtime.
        with self._prediction_lock:
            probs = self.model(
                {"url_input": url_ids, "feature_input": features}, training=False
            ).numpy()
        results = []
        for row in probs:
            idx = int(np.argmax(row))
            results.append(
                {
                    "category": THREAT_CLASSES[idx],
                    "confidence": float(row[idx]),
                    "probabilities": {
                        cls: float(p) for cls, p in zip(THREAT_CLASSES, row)
                    },
                }
            )
        return results


def demo():
    model = build_model()
    assert model.name == MODEL_NAME
    assert model.output_shape[-1] == len(THREAT_CLASSES)

    batch = 4
    fake_url_ids = np.random.randint(
        0, MODEL_CONFIG["vocab_size"], size=(batch, MODEL_CONFIG["max_url_length"])
    ).astype("int32")
    fake_features = np.random.rand(batch, MODEL_CONFIG["num_features"]).astype(
        "float32"
    )

    wrapper = ThreatDetectionModel(model)
    results = wrapper.predict_with_confidence(fake_url_ids, fake_features)
    assert len(results) == batch
    assert set(results[0]["probabilities"].keys()) == set(THREAT_CLASSES)
    assert abs(sum(results[0]["probabilities"].values()) - 1.0) < 1e-4

    print(
        f"model.py: {MODEL_NAME} builds and predicts correctly, "
        f"{model.count_params():,} params"
    )


if __name__ == "__main__":
    demo()
