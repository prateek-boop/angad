"""Training pipeline. See MODEL_BRAIN.md sec 7: load real URLs -> tokenize
-> extract features -> label -> stratified split -> train -> evaluate -> save.

This pipeline is real-data-only. There is no synthetic URL generator: every
training example must come from a real threat feed, a real safe-domain list,
or a locally supplied labeled CSV (see ``--local-csv``)."""

import json
import os

import numpy as np
import tensorflow as tf
from sklearn.metrics import (
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight

import config
from ml_engine.feature_extractor import FeatureExtractor
from ml_engine.model import ThreatDetectionModel, build_model
from ml_engine.real_data_loader import load_real_dataset
from ml_engine.tier5.calibration import TemperatureCalibrator
from ml_engine.tier5.feedback import FeedbackStore
from ml_engine.url_tokenizer import URLTokenizer

_DEFAULT_FEED_NAMES = ["urlhaus", "openphish", "tranco"]


def _deduplicate(urls: list[str], labels: list[str]) -> tuple[list[str], list[str]]:
    if len(urls) != len(labels):
        raise ValueError("dataset URLs and labels have different lengths")
    observed: dict[str, set[str]] = {}
    original: dict[str, str] = {}
    for url, label in zip(urls, labels):
        if label not in config.THREAT_CLASSES:
            raise ValueError(f"unsupported label: {label}")
        key = url.strip().lower()
        if not key:
            continue
        observed.setdefault(key, set()).add(label)
        original.setdefault(key, url.strip())

    clean_urls, clean_labels = [], []
    for key, label_set in observed.items():
        # Conflicting intelligence is unsafe training supervision. Exclude it
        # instead of choosing whichever feed happened to load last.
        if len(label_set) != 1:
            continue
        clean_urls.append(original[key])
        clean_labels.append(next(iter(label_set)))
    return clean_urls, clean_labels


def _expected_calibration_error(
    probabilities: np.ndarray, labels: np.ndarray, bins: int = 15
) -> float:
    confidence = probabilities.max(axis=1)
    predictions = probabilities.argmax(axis=1)
    error = 0.0
    boundaries = np.linspace(0.0, 1.0, bins + 1)
    for lower, upper in zip(boundaries[:-1], boundaries[1:]):
        mask = (confidence > lower) & (confidence <= upper)
        if np.any(mask):
            accuracy = np.mean(predictions[mask] == labels[mask])
            error += float(mask.mean() * abs(accuracy - confidence[mask].mean()))
    return error


def _prepare_arrays(urls: list[str], labels: list[str]):
    tokenizer = URLTokenizer()
    extractor = FeatureExtractor()
    label_to_idx = {c: i for i, c in enumerate(config.THREAT_CLASSES)}

    url_ids = tokenizer.encode_batch(urls)
    features = np.array([extractor.extract(u) for u in urls], dtype=np.float32)
    y = np.array([label_to_idx[label] for label in labels], dtype=np.int64)
    return url_ids, features, y


def load_dataset(
    feed_names: list[str] | None = None,
    *,
    local_csv: list[str] | None = None,
    phishtank_csv: str | None = None,
    include_feedback: bool = False,
    strict: bool = False,
) -> tuple[list[str], list[str]]:
    """Assemble a real-data training set: free threat feeds + optional local CSVs.

    ``urlhaus``/``openphish``/``tranco`` cover malware/phishing/safe automatically.
    Nothing free covers ``data_leak`` or ``scam`` in real time, so those classes
    (and any extra coverage) must come from ``local_csv`` (e.g. a labeled Kaggle
    export with ``url``/``label`` columns) or a manually downloaded PhishTank
    export passed as ``phishtank_csv``.
    """
    names = list(feed_names) if feed_names is not None else list(_DEFAULT_FEED_NAMES)
    sources = {}
    if phishtank_csv:
        sources["phishtank"] = phishtank_csv
        if "phishtank" not in names:
            names.append("phishtank")

    urls, labels = load_real_dataset(
        feed_names=names,
        sources=sources,
        local_sources=local_csv,
        strict=strict,
    )
    if include_feedback:
        reviewed = FeedbackStore().export_labeled_corrections()
        if reviewed:
            extra_urls, extra_labels = zip(*reviewed)
            urls = list(urls) + list(extra_urls)
            labels = list(labels) + list(extra_labels)
    return list(urls), list(labels)


def train(
    feed_names: list[str] | None = None,
    local_csv: list[str] | None = None,
    phishtank_csv: str | None = None,
    include_feedback: bool = False,
    epochs: int | None = None,
    strict: bool = False,
):
    epochs = epochs or config.TRAIN_CONFIG["epochs"]

    np.random.seed(42)
    tf.keras.utils.set_random_seed(42)

    urls, labels = load_dataset(
        feed_names,
        local_csv=local_csv,
        phishtank_csv=phishtank_csv,
        include_feedback=include_feedback,
        strict=strict,
    )
    urls, labels = _deduplicate(urls, labels)
    class_counts = {name: labels.count(name) for name in config.THREAT_CLASSES}
    if min(class_counts.values(), default=0) < 3:
        raise ValueError(
            "each class needs at least three samples after deduplication: "
            f"{class_counts}. Free feeds only cover safe/phishing/malware — "
            "supply --local-csv for data_leak/scam (and any other underfilled "
            "class) with a labeled url,label CSV."
        )
    url_ids, features, y = _prepare_arrays(urls, labels)

    test_frac = config.TRAIN_CONFIG["test_split"]
    val_frac = config.TRAIN_CONFIG["val_split"]

    idx = np.arange(len(y))
    idx_train, idx_test = train_test_split(
        idx, test_size=test_frac, stratify=y, random_state=42
    )
    idx_train, idx_val = train_test_split(
        idx_train,
        test_size=val_frac / (1 - test_frac),
        stratify=y[idx_train],
        random_state=42,
    )

    def subset(indices):
        return {"url_input": url_ids[indices], "feature_input": features[indices]}, y[
            indices
        ]

    x_train, y_train = subset(idx_train)
    x_val, y_val = subset(idx_val)
    x_test, y_test = subset(idx_test)

    model = build_model()
    lr_schedule = tf.keras.optimizers.schedules.CosineDecay(
        config.TRAIN_CONFIG["learning_rate"],
        decay_steps=epochs
        * max(1, len(idx_train) // config.TRAIN_CONFIG["batch_size"]),
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=lr_schedule),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )

    os.makedirs(config.SAVED_MODEL_DIR, exist_ok=True)
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=config.TRAIN_CONFIG["early_stopping_patience"],
            restore_best_weights=True,
        ),
        tf.keras.callbacks.ModelCheckpoint(
            config.BEST_MODEL_PATH,
            monitor="val_accuracy",
            save_best_only=True,
        ),
    ]

    present_classes = np.unique(y_train)
    balanced_weights = compute_class_weight(
        class_weight="balanced", classes=present_classes, y=y_train
    )
    class_weights = {
        int(label): float(min(weight, 5.0))
        for label, weight in zip(present_classes, balanced_weights)
    }

    history = model.fit(
        x_train,
        y_train,
        validation_data=(x_val, y_val),
        batch_size=config.TRAIN_CONFIG["batch_size"],
        epochs=epochs,
        callbacks=callbacks,
        class_weight=class_weights,
        verbose=2,
    )

    test_loss, test_acc = model.evaluate(x_test, y_test, verbose=0)

    val_probs = np.asarray(model.predict(x_val, verbose=0), dtype=np.float64)
    raw_test_probs = np.asarray(model.predict(x_test, verbose=0), dtype=np.float64)
    calibrator = TemperatureCalibrator().fit(val_probs, y_val)
    calibrator.save(config.CALIBRATION_PATH)
    test_probs = calibrator.transform(raw_test_probs)

    per_class_acc = {}
    preds = np.argmax(test_probs, axis=1)
    for i, cls in enumerate(config.THREAT_CLASSES):
        mask = y_test == i
        if mask.sum() > 0:
            per_class_acc[cls] = float((preds[mask] == i).mean())

    metrics = {
        "test_loss": float(test_loss),
        "test_accuracy": float(test_acc),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, preds)),
        "macro_f1": float(f1_score(y_test, preds, average="macro", zero_division=0)),
        "raw_log_loss": float(
            log_loss(
                y_test, raw_test_probs, labels=list(range(len(config.THREAT_CLASSES)))
            )
        ),
        "calibrated_log_loss": float(
            log_loss(y_test, test_probs, labels=list(range(len(config.THREAT_CLASSES))))
        ),
        "raw_expected_calibration_error": _expected_calibration_error(
            raw_test_probs, y_test
        ),
        "calibrated_expected_calibration_error": _expected_calibration_error(
            test_probs, y_test
        ),
        "temperature": calibrator.temperature,
        "per_class_accuracy": per_class_acc,
        "confusion_matrix": confusion_matrix(
            y_test, preds, labels=list(range(len(config.THREAT_CLASSES)))
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            preds,
            labels=list(range(len(config.THREAT_CLASSES))),
            target_names=config.THREAT_CLASSES,
            output_dict=True,
            zero_division=0,
        ),
        "class_counts": class_counts,
        "n_train": len(idx_train),
        "n_val": len(idx_val),
        "n_test": len(idx_test),
        "feed_names": list(feed_names) if feed_names is not None else list(_DEFAULT_FEED_NAMES),
        "local_csv_count": len(local_csv or []),
        "used_phishtank_csv": bool(phishtank_csv),
        "included_feedback": include_feedback,
        "epochs_run": len(history.history["loss"]),
    }
    with open(config.METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    wrapper = ThreatDetectionModel(model)
    wrapper.save(config.MODEL_PATH)

    print(f"Saved model to {config.MODEL_PATH}")
    print(f"Test accuracy: {test_acc:.4f}")
    print(
        f"Calibrated log loss: {metrics['calibrated_log_loss']:.4f} (T={calibrator.temperature:.3f})"
    )
    print(f"Per-class accuracy: {json.dumps(per_class_acc, indent=2)}")
    return metrics


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--feeds", nargs="+", choices=["urlhaus", "openphish", "tranco"], default=None
    )
    parser.add_argument("--local-csv", nargs="+", default=None)
    parser.add_argument("--phishtank-csv", default=None)
    parser.add_argument("--include-feedback", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--epochs", type=int, default=None)
    args = parser.parse_args()

    train(
        feed_names=args.feeds,
        local_csv=args.local_csv,
        phishtank_csv=args.phishtank_csv,
        include_feedback=args.include_feedback,
        epochs=args.epochs,
        strict=args.strict,
    )
