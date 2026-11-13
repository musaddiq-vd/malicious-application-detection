"""Dataset loading, validation, de-duplication and splitting.

The raw CSV has 6,802 rows but only ~1,100 distinct ones: most rows are exact
copies of another row. Splitting such data at random puts copies of the same
row on both sides of the split, so a model is "tested" on rows it was trained
on and its accuracy is inflated. Everything here exists to prevent that:

1. ``load_raw`` reads and strictly validates the CSV (exact columns, 0/1 only).
2. ``deduplicate`` collapses the data to one row per distinct feature vector.
   A few vectors occur with both labels; each is given its majority label
   (by raw row count) and exact ties are dropped as uninformative.
3. ``split`` makes a stratified train/test split of the de-duplicated rows, so
   no feature vector can be on both sides.

Only the standard library and NumPy are used, so loading the data has no heavy
dependencies.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

from maldetect import config
from maldetect.features import FEATURES, TARGET, keys

RANDOM_STATE = 42
TEST_SIZE = 0.2


class DatasetError(ValueError):
    """The CSV does not have the expected shape or values."""


@dataclass(frozen=True)
class RawData:
    """The CSV exactly as stored: one row per sample, duplicates included."""

    X: np.ndarray  # (n_rows, 35) int8, columns in catalog order
    y: np.ndarray  # (n_rows,) int8, 1 = malicious


@dataclass(frozen=True)
class DedupStats:
    rows_raw: int
    rows_unique: int  # distinct (features, label) rows
    duplicates_removed: int  # rows_raw - rows_unique
    unique_feature_vectors: int
    conflicting_groups: int  # feature vectors seen with both labels
    conflicts_resolved_by_majority: int
    conflicts_dropped_as_ties: int
    rows_modeling: int  # rows actually used for training and evaluation


@dataclass(frozen=True)
class CleanData:
    """One row per distinct feature vector with a single resolved label."""

    X: np.ndarray  # (n, 35) int8
    y: np.ndarray  # (n,) int8
    counts: np.ndarray  # (n,) how many raw rows collapsed into each row
    stats: DedupStats


@dataclass(frozen=True)
class Split:
    X_train: np.ndarray
    X_test: np.ndarray
    y_train: np.ndarray
    y_test: np.ndarray


def load_raw(path: Path | None = None) -> RawData:
    """Read the CSV and validate it; raises ``DatasetError`` on any surprise."""
    path = path or config.DATA_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            raise DatasetError("Dataset is empty") from None
        rows = [row for row in reader if row]

    expected = [*keys(), TARGET]
    if set(header) != set(expected) or len(header) != len(expected):
        missing = sorted(set(expected) - set(header))
        extra = sorted(set(header) - set(expected))
        raise DatasetError(f"Unexpected columns. Missing: {missing}; unexpected: {extra}")
    if not rows:
        raise DatasetError("Dataset has a header but no rows")

    width = len(header)
    for line_no, row in enumerate(rows, start=2):
        if len(row) != width:
            raise DatasetError(f"Line {line_no}: expected {width} values, found {len(row)}")
        for value in row:
            if value not in ("0", "1"):
                raise DatasetError(f"Line {line_no}: value {value!r} is not 0 or 1")

    table = np.array(rows, dtype=np.int8)
    # Reorder by name so a CSV with shuffled columns still lines up with the catalog.
    order = [header.index(name) for name in expected]
    table = table[:, order]
    return RawData(X=table[:, :-1], y=table[:, -1])


def deduplicate(raw: RawData) -> CleanData:
    """Collapse to one row per distinct feature vector with a majority label."""
    full = np.column_stack([raw.X, raw.y])
    rows_unique = len(np.unique(full, axis=0))

    vectors, inverse, counts = np.unique(raw.X, axis=0, return_inverse=True, return_counts=True)
    inverse = inverse.ravel()
    malicious = np.bincount(inverse, weights=raw.y, minlength=len(vectors)).astype(np.int64)
    benign = counts - malicious

    conflicting = (malicious > 0) & (benign > 0)
    ties = conflicting & (malicious == benign)
    keep = ~ties
    labels = (malicious > benign).astype(np.int8)

    stats = DedupStats(
        rows_raw=len(raw.y),
        rows_unique=int(rows_unique),
        duplicates_removed=int(len(raw.y) - rows_unique),
        unique_feature_vectors=int(len(vectors)),
        conflicting_groups=int(conflicting.sum()),
        conflicts_resolved_by_majority=int((conflicting & ~ties).sum()),
        conflicts_dropped_as_ties=int(ties.sum()),
        rows_modeling=int(keep.sum()),
    )
    return CleanData(
        X=vectors[keep].astype(np.int8),
        y=labels[keep],
        counts=counts[keep].astype(np.int64),
        stats=stats,
    )


def split(
    data: CleanData, test_size: float = TEST_SIZE, random_state: int = RANDOM_STATE
) -> Split:
    """Stratified train/test split of de-duplicated rows."""
    # float64 on purpose: some estimators accumulate counts in the input dtype and would
    # silently overflow on int8.
    X_train, X_test, y_train, y_test = train_test_split(
        data.X.astype(np.float64),
        data.y.astype(np.int64),
        test_size=test_size,
        random_state=random_state,
        stratify=data.y,
    )
    return Split(X_train, X_test, y_train, y_test)


def overlap_fraction(X_train: np.ndarray, X_test: np.ndarray) -> float:
    """Fraction of test rows whose exact feature vector also occurs in the training rows."""
    if len(X_test) == 0:
        return 0.0
    seen = {row.tobytes() for row in np.ascontiguousarray(X_train)}
    hits = sum(row.tobytes() in seen for row in np.ascontiguousarray(X_test))
    return hits / len(X_test)


def feature_prevalence(X: np.ndarray, y: np.ndarray) -> list[dict[str, object]]:
    """Share of benign and of malicious rows that have each feature set."""
    benign, malicious = X[y == 0], X[y == 1]
    return [
        {
            "slug": feature.slug,
            "label": feature.label,
            "category": feature.category,
            "benign_rate": float(benign[:, i].mean()) if len(benign) else 0.0,
            "malicious_rate": float(malicious[:, i].mean()) if len(malicious) else 0.0,
        }
        for i, feature in enumerate(FEATURES)
    ]
