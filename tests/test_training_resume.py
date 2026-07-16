import json

import pytest

import config
from main import build_parser
from ml_engine import train_model


class _Iterations:
    def __init__(self, value):
        self.value = value

    def numpy(self):
        return self.value


class _Optimizer:
    def __init__(self, iterations):
        self.iterations = _Iterations(iterations)


class _Model:
    def __init__(self, iterations):
        self.optimizer = _Optimizer(iterations)


def test_auto_resume_prefers_latest_checkpoint(tmp_path, monkeypatch):
    latest = tmp_path / "last.keras"
    best = tmp_path / "best.keras"
    latest.touch()
    best.touch()
    monkeypatch.setattr(config, "LAST_CHECKPOINT_PATH", str(latest))
    monkeypatch.setattr(config, "BEST_MODEL_PATH", str(best))

    assert train_model._resolve_resume_checkpoint("auto") == str(latest)


def test_default_auto_resume_uses_best_checkpoint_when_latest_is_missing(
    tmp_path, monkeypatch
):
    latest = tmp_path / "last.keras"
    best = tmp_path / "best.keras"
    best.touch()
    monkeypatch.setattr(config, "LAST_CHECKPOINT_PATH", str(latest))
    monkeypatch.setattr(config, "BEST_MODEL_PATH", str(best))

    assert (
        train_model._resolve_resume_checkpoint("auto_if_available") == str(best)
    )


def test_default_auto_resume_allows_first_training_run(tmp_path, monkeypatch):
    monkeypatch.setattr(
        config, "LAST_CHECKPOINT_PATH", str(tmp_path / "missing-last.keras")
    )
    monkeypatch.setattr(
        config, "BEST_MODEL_PATH", str(tmp_path / "missing-best.keras")
    )

    assert train_model._resolve_resume_checkpoint("auto_if_available") is None


def test_train_cli_resumes_by_default_and_restart_is_explicit():
    parser = build_parser()

    default_args = parser.parse_args(["train"])
    restart_args = parser.parse_args(["train", "--restart"])

    assert default_args.resume == "auto_if_available"
    assert restart_args.resume is False


def test_resume_epoch_is_inferred_from_optimizer_iterations(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "TRAINING_STATE_PATH", str(tmp_path / "missing.json"))

    epoch, state = train_model._checkpoint_epoch(
        _Model(iterations=90),
        checkpoint_path=str(tmp_path / "best.keras"),
        steps_per_epoch=10,
        dataset_fingerprint="dataset",
        n_train=100,
        batch_size=10,
    )

    assert epoch == 9
    assert state is None


def test_resume_rejects_changed_dataset(tmp_path, monkeypatch):
    checkpoint = tmp_path / "last.keras"
    checkpoint.touch()
    state_path = tmp_path / "training_state.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "checkpoint_path": str(checkpoint),
                "completed_epochs": 2,
                "optimizer_iterations": 20,
                "dataset_fingerprint": "old-dataset",
                "n_train": 100,
                "batch_size": 10,
                "steps_per_epoch": 10,
            }
        )
    )
    monkeypatch.setattr(config, "TRAINING_STATE_PATH", str(state_path))

    with pytest.raises(ValueError, match="does not match"):
        train_model._checkpoint_epoch(
            _Model(iterations=20),
            checkpoint_path=str(checkpoint),
            steps_per_epoch=10,
            dataset_fingerprint="new-dataset",
            n_train=100,
            batch_size=10,
        )


def test_resume_rejects_partial_epoch_without_batch_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "TRAINING_STATE_PATH", str(tmp_path / "missing.json"))

    with pytest.raises(ValueError, match="not an epoch boundary"):
        train_model._checkpoint_epoch(
            _Model(iterations=21),
            checkpoint_path=str(tmp_path / "last.keras"),
            steps_per_epoch=10,
            dataset_fingerprint="dataset",
            n_train=100,
            batch_size=10,
        )
