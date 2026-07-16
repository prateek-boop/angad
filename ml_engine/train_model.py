"""Training pipeline. See MODEL_BRAIN.md sec 7: load real URLs -> tokenize
-> extract features -> label -> stratified split -> train -> evaluate -> save.

This pipeline is real-data-only. There is no synthetic URL generator: every
training example must come from a real threat feed, a real safe-domain list,
or a locally supplied labeled CSV (see ``--local-csv``)."""

import hashlib
import json
import os
import warnings
from pathlib import Path
from typing import Any

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
_AUTO_RESUME = "auto"
_AUTO_RESUME_IF_AVAILABLE = "auto_if_available"
_TRAINING_STATE_VERSION = 1


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


def _dataset_fingerprint(urls: list[str], labels: list[str]) -> str:
    """Identify the exact ordered dataset used to create a checkpoint."""
    digest = hashlib.sha256()
    for url, label in zip(urls, labels):
        digest.update(url.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
        digest.update(label.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _atomic_write_json(path: str, value: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary_path = f"{path}.tmp"
    with open(temporary_path, "w") as handle:
        json.dump(value, handle, indent=2)
    os.replace(temporary_path, path)


def _load_training_state(path: str | None = None) -> dict[str, Any] | None:
    path = path or config.TRAINING_STATE_PATH
    try:
        with open(path) as handle:
            state = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        warnings.warn(f"ignoring unreadable training state at {path}: {exc}", stacklevel=2)
        return None
    return state if isinstance(state, dict) else None


def _resolve_resume_checkpoint(resume_from: str | os.PathLike[str] | bool | None) -> str | None:
    if resume_from in (None, False):
        return None

    resume_value = os.fspath(resume_from) if resume_from is not True else _AUTO_RESUME
    if resume_value in {_AUTO_RESUME, _AUTO_RESUME_IF_AVAILABLE}:
        candidates = (config.LAST_CHECKPOINT_PATH, config.BEST_MODEL_PATH)
        checkpoint_path = next((path for path in candidates if os.path.isfile(path)), None)
        if checkpoint_path is None and resume_value == _AUTO_RESUME:
            raise FileNotFoundError(
                "no resumable checkpoint found; expected "
                f"{config.LAST_CHECKPOINT_PATH} or {config.BEST_MODEL_PATH}"
            )
        return checkpoint_path

    checkpoint_path = os.path.abspath(os.path.expanduser(os.fspath(resume_from)))
    if not os.path.isfile(checkpoint_path):
        raise FileNotFoundError(f"resume checkpoint not found: {checkpoint_path}")
    return checkpoint_path


def _optimizer_iterations(model: tf.keras.Model) -> int:
    optimizer = getattr(model, "optimizer", None)
    if optimizer is None:
        raise ValueError(
            "resume checkpoint has no optimizer state; use a full .keras checkpoint"
        )
    return int(optimizer.iterations.numpy())


def _checkpoint_epoch(
    model: tf.keras.Model,
    *,
    checkpoint_path: str,
    steps_per_epoch: int,
    dataset_fingerprint: str,
    n_train: int,
    batch_size: int,
) -> tuple[int, dict[str, Any] | None]:
    iterations = _optimizer_iterations(model)
    inferred_epoch, partial_epoch_steps = divmod(iterations, steps_per_epoch)
    if partial_epoch_steps:
        raise ValueError(
            f"checkpoint optimizer is at step {iterations}, which is not an epoch "
            f"boundary for {steps_per_epoch} steps per epoch"
        )

    state = _load_training_state()
    if not state:
        return inferred_epoch, None

    state_checkpoint = state.get("checkpoint_path")
    try:
        same_checkpoint = state_checkpoint is not None and Path(state_checkpoint).resolve() == Path(
            checkpoint_path
        ).resolve()
    except (OSError, RuntimeError):
        same_checkpoint = False
    if not same_checkpoint:
        return inferred_epoch, None

    expected = {
        "version": _TRAINING_STATE_VERSION,
        "dataset_fingerprint": dataset_fingerprint,
        "n_train": n_train,
        "batch_size": batch_size,
        "steps_per_epoch": steps_per_epoch,
    }
    mismatches = {
        key: (state.get(key), value)
        for key, value in expected.items()
        if state.get(key) != value
    }
    if mismatches:
        details = ", ".join(
            f"{key} checkpoint={actual!r} current={expected_value!r}"
            for key, (actual, expected_value) in mismatches.items()
        )
        raise ValueError(
            "checkpoint does not match the current dataset/training configuration: "
            f"{details}"
        )

    completed_epochs = int(state.get("completed_epochs", inferred_epoch))
    state_iterations = int(state.get("optimizer_iterations", iterations))
    if completed_epochs != inferred_epoch or state_iterations != iterations:
        warnings.warn(
            "training_state.json is stale; using the epoch inferred from the "
            "checkpoint optimizer state",
            stacklevel=2,
        )
        return inferred_epoch, None
    return completed_epochs, state


class _TrainingStateCallback(tf.keras.callbacks.Callback):
    def __init__(
        self,
        *,
        checkpoint_path: str,
        dataset_fingerprint: str,
        n_train: int,
        batch_size: int,
        steps_per_epoch: int,
        best_val_accuracy: float | None,
    ):
        super().__init__()
        self.checkpoint_path = os.path.abspath(checkpoint_path)
        self.dataset_fingerprint = dataset_fingerprint
        self.n_train = n_train
        self.batch_size = batch_size
        self.steps_per_epoch = steps_per_epoch
        self.best_val_accuracy = best_val_accuracy

    def on_epoch_end(self, epoch, logs=None):
        logs = logs or {}
        val_accuracy = logs.get("val_accuracy")
        if val_accuracy is not None:
            val_accuracy = float(val_accuracy)
            if self.best_val_accuracy is None or val_accuracy > self.best_val_accuracy:
                self.best_val_accuracy = val_accuracy

        state = {
            "version": _TRAINING_STATE_VERSION,
            "checkpoint_path": self.checkpoint_path,
            "completed_epochs": int(epoch) + 1,
            "optimizer_iterations": _optimizer_iterations(self.model),
            "dataset_fingerprint": self.dataset_fingerprint,
            "n_train": self.n_train,
            "batch_size": self.batch_size,
            "steps_per_epoch": self.steps_per_epoch,
            "best_val_accuracy": self.best_val_accuracy,
        }
        _atomic_write_json(config.TRAINING_STATE_PATH, state)


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
    # A local CSV without explicit feed_names means feeds are opt-in, not default.
    names = (
        list(feed_names)
        if feed_names is not None
        else ([] if local_csv else list(_DEFAULT_FEED_NAMES))
    )
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
    resume_from: str | os.PathLike[str] | bool | None = None,
):
    epochs = config.TRAIN_CONFIG["epochs"] if epochs is None else epochs
    if epochs < 1:
        raise ValueError("epochs must be at least 1")

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
    dataset_fingerprint = _dataset_fingerprint(urls, labels)
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

    os.makedirs(config.SAVED_MODEL_DIR, exist_ok=True)
    batch_size = config.TRAIN_CONFIG["batch_size"]
    steps_per_epoch = max(1, (len(idx_train) + batch_size - 1) // batch_size)
    checkpoint_path = _resolve_resume_checkpoint(resume_from)
    initial_epoch = 0
    resume_state = None
    if checkpoint_path:
        model = ThreatDetectionModel.load(checkpoint_path).model
        initial_epoch, resume_state = _checkpoint_epoch(
            model,
            checkpoint_path=checkpoint_path,
            steps_per_epoch=steps_per_epoch,
            dataset_fingerprint=dataset_fingerprint,
            n_train=len(idx_train),
            batch_size=batch_size,
        )
        if initial_epoch >= epochs:
            raise ValueError(
                f"checkpoint already completed {initial_epoch} epochs; "
                f"--epochs is the total target, so choose a value above {initial_epoch}"
            )
        print(
            f"Resuming from {checkpoint_path} at epoch {initial_epoch + 1}/{epochs} "
            f"(optimizer step {_optimizer_iterations(model)})"
        )
    else:
        model = build_model()
        lr_schedule = tf.keras.optimizers.schedules.CosineDecay(
            config.TRAIN_CONFIG["learning_rate"],
            decay_steps=epochs * max(1, len(idx_train) // batch_size),
        )
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=lr_schedule),
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )

    best_val_accuracy = None
    if resume_state and resume_state.get("best_val_accuracy") is not None:
        best_val_accuracy = float(resume_state["best_val_accuracy"])
    elif (
        checkpoint_path
        and os.path.isfile(config.BEST_MODEL_PATH)
        and os.path.samefile(checkpoint_path, config.BEST_MODEL_PATH)
    ):
        validation_metrics = model.evaluate(x_val, y_val, verbose=0, return_dict=True)
        best_val_accuracy = float(validation_metrics["accuracy"])

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
            initial_value_threshold=best_val_accuracy,
        ),
        tf.keras.callbacks.ModelCheckpoint(
            config.LAST_CHECKPOINT_PATH,
            save_best_only=False,
        ),
        _TrainingStateCallback(
            checkpoint_path=config.LAST_CHECKPOINT_PATH,
            dataset_fingerprint=dataset_fingerprint,
            n_train=len(idx_train),
            batch_size=batch_size,
            steps_per_epoch=steps_per_epoch,
            best_val_accuracy=best_val_accuracy,
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
        batch_size=batch_size,
        initial_epoch=initial_epoch,
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
        "resumed_from": checkpoint_path,
        "initial_epoch": initial_epoch,
        "epochs_run": len(history.history["loss"]),
        "epochs_completed": initial_epoch + len(history.history["loss"]),
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
    parser.add_argument(
        "--epochs",
        type=int,
        default=None,
        help="total target epoch count; completed checkpoint epochs are skipped",
    )
    resume_group = parser.add_mutually_exclusive_group()
    resume_group.add_argument(
        "--resume",
        nargs="?",
        const=_AUTO_RESUME,
        default=_AUTO_RESUME_IF_AVAILABLE,
        metavar="CHECKPOINT",
        help="resume automatically from the latest checkpoint (the default); "
        "optionally provide a checkpoint path",
    )
    resume_group.add_argument(
        "--restart",
        action="store_const",
        const=False,
        dest="resume",
        help="ignore existing checkpoints and start again at epoch 1",
    )
    args = parser.parse_args()

    train(
        feed_names=args.feeds,
        local_csv=args.local_csv,
        phishtank_csv=args.phishtank_csv,
        include_feedback=args.include_feedback,
        epochs=args.epochs,
        strict=args.strict,
        resume_from=args.resume,
    )
