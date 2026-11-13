"""Model-agnostic, per-prediction explanations.

For a submitted feature vector ``x`` the impact of feature ``i`` is

    impact_i = P(malicious | x) - P(malicious | x with feature i flipped)

A positive impact means the feature's current value pushes the verdict towards
"malicious": a set feature whose removal would lower the probability, or an
unset feature whose presence would lower it. This works with any classifier
that exposes ``predict_proba`` and needs no access to its internals.

Impacts are one-at-a-time effects. They do not sum to the probability and they
ignore interactions between features, so read them as "what would change if
this one answer were different", not as an additive decomposition.
"""

from __future__ import annotations

from typing import Protocol

import numpy as np


class ProbabilisticModel(Protocol):
    def predict_proba(self, X: np.ndarray) -> np.ndarray: ...


def flip_matrix(x: np.ndarray) -> np.ndarray:
    """Stack ``x`` with its n single-feature flips: shape (n + 1, n), row 0 is ``x``."""
    x = np.asarray(x, dtype=np.float64).ravel()
    n = x.shape[0]
    batch = np.tile(x, (n + 1, 1))
    idx = np.arange(n)
    batch[idx + 1, idx] = 1.0 - batch[idx + 1, idx]
    return batch


def flip_impacts(model: ProbabilisticModel, x: np.ndarray) -> tuple[float, np.ndarray]:
    """Return ``(P(malicious | x), impacts)`` using a single batched model call."""
    proba = np.asarray(model.predict_proba(flip_matrix(x)))[:, 1]
    base = float(proba[0])
    return base, base - proba[1:]
