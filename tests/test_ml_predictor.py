"""Tests for prediction and explanation, using the committed model artifact.

Nothing here retrains the full model. Where a model is needed independently of
the artifact, a tiny logistic regression is fitted on a handful of rows.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from maldetect import config
from maldetect.features import CATEGORIES, slugs
from maldetect.ml.explain import flip_impacts, flip_matrix
from maldetect.ml.predictor import Prediction, Predictor, risk_level

needs_artifact = pytest.mark.skipif(
    not config.MODEL_PATH.is_file(), reason="model not trained (python -m maldetect.ml.train)"
)

SPYWARE = {
    "telephony_get_device_id": 1,
    "telephony_get_subscriber_id": 1,
    "send_sms": 1,
    "receive_sms": 1,
    "read_sms": 1,
    "read_phone_state": 1,
    "abort_broadcast": 1,
    "boot_completed": 1,
    "internet": 1,
    "inet_socket_address": 1,
}


@pytest.fixture(scope="module")
def predictor() -> Predictor:
    if not config.MODEL_PATH.is_file():
        pytest.skip("model not trained")
    return Predictor.load()


class _Linear:
    """A fixed logistic model: P = sigmoid(w . x + b)."""

    def __init__(self, w: np.ndarray, b: float) -> None:
        self.w, self.b = w, b
        self.calls = 0

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        self.calls += 1
        p = 1 / (1 + np.exp(-(X @ self.w + self.b)))
        return np.column_stack([1 - p, p])


def _tiny_model() -> LogisticRegression:
    rng = np.random.default_rng(0)
    X = rng.integers(0, 2, size=(80, 35)).astype(float)
    y = (X[:, 0] + X[:, 3] >= 1).astype(int)
    return LogisticRegression().fit(X, y)


# --------------------------------------------------------------------------- explain


def test_flip_matrix() -> None:
    x = np.array([1.0, 0.0, 1.0])
    batch = flip_matrix(x)
    assert batch.shape == (4, 3)
    assert batch[0].tolist() == [1, 0, 1]
    assert batch[1].tolist() == [0, 0, 1]
    assert batch[2].tolist() == [1, 1, 1]
    assert batch[3].tolist() == [1, 0, 0]


def test_flip_impacts_signs_and_single_call() -> None:
    w = np.zeros(35)
    w[0], w[1] = 3.0, -3.0
    model = _Linear(w, b=-1.0)
    x = np.zeros(35)
    x[0] = 1.0
    base, impacts = flip_impacts(model, x)
    assert model.calls == 1
    assert base == pytest.approx(1 / (1 + np.exp(-2.0)))
    assert impacts[0] > 0  # present and malicious-leaning: pushes towards malicious
    assert impacts[1] > 0  # absent and benign-leaning: its absence pushes towards malicious
    assert np.allclose(impacts[2:], 0.0)


# --------------------------------------------------------------------------- predictor (tiny model)


def test_predictor_with_tiny_model(tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    joblib.dump(
        {"model": _tiny_model(), "feature_slugs": slugs(), "threshold": 0.5,
         "model_name": "Tiny", "metadata": {}},
        path,
    )
    predictor = Predictor.load(path)
    result = predictor.predict({"telephony_get_device_id": 1})
    assert result.model_name == "Tiny"
    assert len(result.contributions) == 35
    assert result.contributions[0].slug in {"telephony_get_device_id", "send_sms"}


def test_predictor_rejects_mismatched_feature_set(tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    joblib.dump(
        {"model": _tiny_model(), "feature_slugs": slugs()[:-1], "threshold": 0.5,
         "model_name": "Tiny"},
        path,
    )
    with pytest.raises(ValueError, match="different feature set"):
        Predictor.load(path)


def test_load_missing_model(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        Predictor.load(tmp_path / "absent.joblib")


@pytest.mark.parametrize(
    ("p", "level"),
    [(0.0, "low"), (0.249, "low"), (0.25, "medium"), (0.49, "medium"), (0.5, "high"),
     (0.79, "high"), (0.8, "critical"), (1.0, "critical")],
)
def test_risk_levels(p: float, level: str) -> None:
    assert risk_level(p) == level


# --------------------------------------------------------------------------- committed artifact


@needs_artifact
def test_artifact_predicts_spyware_as_malicious(predictor: Predictor) -> None:
    result = predictor.predict(SPYWARE)
    assert isinstance(result, Prediction)
    assert result.verdict == "malicious"
    assert result.probability > 0.8
    assert result.risk_level == "critical"


@needs_artifact
def test_artifact_predicts_empty_app_as_benign(predictor: Predictor) -> None:
    result = predictor.predict({})
    assert result.verdict == "benign"
    assert result.probability < predictor.threshold


@needs_artifact
def test_contributions_complete_sorted_and_consistent(predictor: Predictor) -> None:
    result = predictor.predict(SPYWARE)
    contributions = result.contributions
    assert [c.slug for c in contributions] != []
    assert {c.slug for c in contributions} == set(slugs())
    impacts = [abs(c.impact) for c in contributions]
    assert impacts == sorted(impacts, reverse=True)
    for c in contributions:
        assert c.category in CATEGORIES
        assert c.value == SPYWARE.get(c.slug, 0)

    # Cross-check one impact by flipping that feature by hand.
    top = contributions[0]
    flipped = dict(SPYWARE)
    flipped[top.slug] = 1 - top.value
    other = predictor.predict(flipped).probability
    assert top.impact == pytest.approx(result.probability - other, abs=1e-9)


@needs_artifact
def test_to_dict_is_json_serialisable(predictor: Predictor) -> None:
    payload = predictor.predict(SPYWARE).to_dict()
    text = json.dumps(payload)
    assert set(payload) == {
        "verdict", "probability", "risk_level", "threshold", "model_name", "contributions"
    }
    assert set(payload["contributions"][0]) == {"slug", "label", "category", "value", "impact"}
    assert "malicious" in text


@needs_artifact
@pytest.mark.parametrize(
    "features",
    [{"not_a_feature": 1}, {"send_sms": 2}, {"send_sms": -1}, {"send_sms": "1"},
     {"send_sms": 1.0}, {"send_sms": None}],
)
def test_invalid_input_raises(predictor: Predictor, features: dict) -> None:
    with pytest.raises(ValueError):
        predictor.predict(features)


@needs_artifact
def test_bool_values_are_accepted(predictor: Predictor) -> None:
    assert predictor.predict({"send_sms": True}).contributions


@needs_artifact
def test_artifact_bundle_metadata() -> None:
    bundle = joblib.load(config.MODEL_PATH)
    assert bundle["feature_slugs"] == slugs()
    assert 0.0 < bundle["threshold"] < 1.0
    assert bundle["model_name"]
    assert hasattr(bundle["model"], "predict_proba")
