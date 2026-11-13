"""Loading the trained model and scoring a single app.

This is the only ML entry point the web API uses. ``Predictor.load`` reads the
bundle written by ``python -m maldetect.ml.train``; ``Predictor.predict`` turns
a ``{slug: 0/1}`` mapping into a verdict, a calibrated probability and a
per-feature explanation.

The bundle is a joblib (pickle) file. Only load bundles you produced yourself:
unpickling a file from an untrusted source can execute arbitrary code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from maldetect import config
from maldetect.features import by_slug, slugs
from maldetect.ml.explain import flip_impacts

RISK_LEVELS: tuple[tuple[float, str], ...] = ((0.25, "low"), (0.5, "medium"), (0.8, "high"))


def risk_level(probability: float) -> str:
    """Map a malicious probability onto low / medium / high / critical."""
    for upper, name in RISK_LEVELS:
        if probability < upper:
            return name
    return "critical"


@dataclass(frozen=True)
class Contribution:
    slug: str
    label: str
    category: str
    value: int
    impact: float


@dataclass(frozen=True)
class Prediction:
    verdict: str
    probability: float
    risk_level: str
    threshold: float
    model_name: str
    contributions: list[Contribution]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Predictor:
    """A trained, calibrated classifier plus the metadata needed to use it."""

    def __init__(
        self,
        model: Any,
        feature_slugs: list[str],
        threshold: float,
        model_name: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if feature_slugs != slugs():
            raise ValueError(
                "Model was trained on a different feature set than the current catalog; retrain "
                "with `python -m maldetect.ml.train`."
            )
        self.model = model
        self.feature_slugs = list(feature_slugs)
        self.threshold = float(threshold)
        self.model_name = model_name
        self.metadata: dict[str, Any] = dict(metadata or {})
        self._index = {slug: i for i, slug in enumerate(self.feature_slugs)}

    @classmethod
    def load(cls, model_path: Path | None = None) -> Predictor:
        """Load the model bundle; raises ``FileNotFoundError`` if it has not been trained."""
        path = Path(model_path) if model_path is not None else config.MODEL_PATH
        if not path.is_file():
            raise FileNotFoundError(
                f"No trained model at {path}. Run `python -m maldetect.ml.train` first."
            )
        bundle = joblib.load(path)
        return cls(
            model=bundle["model"],
            feature_slugs=list(bundle["feature_slugs"]),
            threshold=float(bundle["threshold"]),
            model_name=str(bundle["model_name"]),
            metadata=bundle.get("metadata"),
        )

    def vectorize(self, features: Mapping[str, int]) -> np.ndarray:
        """Validate a ``{slug: 0/1}`` mapping and return it as a model input row."""
        x = np.zeros(len(self.feature_slugs), dtype=np.float64)
        for slug, value in features.items():
            position = self._index.get(slug)
            if position is None:
                raise ValueError(f"Unknown feature: {slug!r}")
            # bool is accepted (it is an int); floats and strings are not, even "1" or 1.0,
            # so a malformed client cannot silently submit something other than a yes/no.
            if not isinstance(value, (int, np.integer)) or value not in (0, 1):
                raise ValueError(f"Feature {slug!r} must be 0 or 1, got {value!r}")
            x[position] = float(value)
        return x

    def predict(self, features: Mapping[str, int]) -> Prediction:
        """Score one app. Missing slugs count as 0; unknown slugs or non-0/1 values raise."""
        x = self.vectorize(features)
        probability, impacts = flip_impacts(self.model, x)
        probability = min(1.0, max(0.0, probability))

        contributions = []
        for slug, value, impact in zip(self.feature_slugs, x, impacts, strict=True):
            feature = by_slug(slug)
            contributions.append(
                Contribution(
                    slug=slug,
                    label=feature.label,
                    category=feature.category,
                    value=int(value),
                    impact=float(impact),
                )
            )
        contributions.sort(key=lambda c: abs(c.impact), reverse=True)

        return Prediction(
            verdict="malicious" if probability >= self.threshold else "benign",
            probability=probability,
            risk_level=risk_level(probability),
            threshold=self.threshold,
            model_name=self.model_name,
            contributions=contributions,
        )
