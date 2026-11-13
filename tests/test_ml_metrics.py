"""Schema checks for the committed models/metrics.json (no retraining)."""

from __future__ import annotations

import json
from typing import Any

import numpy as np
import pytest

from maldetect import config
from maldetect.features import slugs
from maldetect.ml.train import choose_threshold, classification_metrics

TEST_KEYS = {"accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc"}
CV_KEYS = {"accuracy_mean", "accuracy_std", "f1_mean", "f1_std", "roc_auc_mean", "roc_auc_std"}


@pytest.fixture(scope="module")
def metrics() -> dict[str, Any]:
    if not config.METRICS_PATH.is_file():
        pytest.skip("metrics not generated (python -m maldetect.ml.train)")
    return json.loads(config.METRICS_PATH.read_text(encoding="utf-8"))


def _is_rate(value: Any) -> bool:
    return isinstance(value, float | int) and 0.0 <= value <= 1.0


def test_top_level_keys(metrics: dict[str, Any]) -> None:
    for key in ("trained_at", "sklearn_version", "dataset", "split", "best_model", "threshold",
                "models", "best", "legacy_baseline"):
        assert key in metrics
    assert metrics["trained_at"].endswith("Z")
    assert _is_rate(metrics["threshold"])


def test_dataset_block(metrics: dict[str, Any]) -> None:
    d = metrics["dataset"]
    assert d["rows_raw"] == 6802
    assert d["rows_unique"] == 1107
    assert d["duplicates_removed"] == 5695
    assert d["n_features"] == 35
    assert d["class_balance_raw"] == {"benign": 4873, "malicious": 1929}
    assert set(d["class_balance_unique"]) == {"benign", "malicious"}
    assert [p["slug"] for p in d["feature_prevalence"]] == slugs()
    for p in d["feature_prevalence"]:
        assert _is_rate(p["benign_rate"]) and _is_rate(p["malicious_rate"])


def test_split_block(metrics: dict[str, Any]) -> None:
    s = metrics["split"]
    assert {"strategy", "train_rows", "test_rows", "cv_folds", "random_state"} <= set(s)
    total = metrics["dataset"]["class_balance_unique"]
    assert s["train_rows"] + s["test_rows"] == total["benign"] + total["malicious"]


def test_models_block(metrics: dict[str, Any]) -> None:
    names = [m["name"] for m in metrics["models"]]
    assert metrics["best_model"] in names
    assert len(names) >= 5
    for model in metrics["models"]:
        assert set(model["cv"]) == CV_KEYS
        assert set(model["test"]) == TEST_KEYS
        assert all(_is_rate(v) for v in model["test"].values())
        assert isinstance(model["params"], dict)
        assert model["fit_seconds"] >= 0


def test_best_block(metrics: dict[str, Any]) -> None:
    best = metrics["best"]
    assert set(best["test"]) == TEST_KEYS
    cm = best["confusion_matrix"]
    assert set(cm) == {"tn", "fp", "fn", "tp"}
    assert sum(cm.values()) == metrics["split"]["test_rows"]
    assert len(best["roc_curve"]["fpr"]) == len(best["roc_curve"]["tpr"]) <= 100
    assert len(best["pr_curve"]["precision"]) == len(best["pr_curve"]["recall"]) <= 100
    cal = best["calibration"]
    assert len(cal["mean_predicted"]) == len(cal["fraction_positive"]) > 0
    importance = [i["importance"] for i in best["feature_importance"]]
    assert len(importance) == 35
    assert importance == sorted(importance, reverse=True)
    assert {"slug", "label", "category", "importance", "std"} <= set(best["feature_importance"][0])


def test_legacy_block(metrics: dict[str, Any]) -> None:
    legacy = metrics["legacy_baseline"]
    for key in ("reported_accuracy", "leak_free_accuracy", "leak_free_f1",
                "test_rows_also_in_train_pct"):
        assert _is_rate(legacy[key])
    assert legacy["description"]
    # Most of the legacy test rows were copies of training rows.
    assert legacy["test_rows_also_in_train_pct"] > 0.5


def test_choose_threshold_prefers_recall() -> None:
    y = np.array([0, 0, 0, 0, 1, 1])
    p = np.array([0.1, 0.2, 0.35, 0.36, 0.38, 0.9])
    # Catching the second positive at 0.38 is worth one false alarm under F2.
    assert choose_threshold(y, p) <= 0.38


def test_classification_metrics() -> None:
    y = np.array([0, 1, 1, 0])
    p = np.array([0.1, 0.9, 0.4, 0.6])
    m = classification_metrics(y, p, 0.5)
    assert set(m) == TEST_KEYS
    assert m["accuracy"] == 0.5
    assert m["roc_auc"] == 0.75
