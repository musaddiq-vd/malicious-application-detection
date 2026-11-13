"""Tests for dataset loading, validation, de-duplication and splitting."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from maldetect.features import FEATURES, TARGET, by_key, by_slug, keys, slugs
from maldetect.ml import data
from maldetect.ml.data import DatasetError, RawData


def _write_csv(path: Path, rows: list[list[int]], header: list[str] | None = None) -> Path:
    header = header or [*keys(), TARGET]
    lines = [",".join(header)] + [",".join(str(v) for v in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _row(ones: tuple[int, ...] = (), label: int = 0) -> list[int]:
    row = [0] * len(FEATURES)
    for i in ones:
        row[i] = 1
    return [*row, label]


def test_catalog_is_complete_and_consistent() -> None:
    assert len(FEATURES) == 35
    assert len(set(slugs())) == 35
    for feature in FEATURES:
        assert by_slug(feature.slug) is feature
        assert by_key(feature.key) is feature
        assert feature.slug == feature.slug.lower()
        assert feature.description.endswith(".")


def test_real_dataset_matches_catalog() -> None:
    raw = data.load_raw()
    assert raw.X.shape == (6802, 35)
    assert set(np.unique(raw.X)) <= {0, 1}
    assert int(raw.y.sum()) == 1929


def test_load_rejects_bad_values(tmp_path: Path) -> None:
    rows = [_row(), _row(label=1)]
    rows[1][3] = 2
    with pytest.raises(DatasetError, match="not 0 or 1"):
        data.load_raw(_write_csv(tmp_path / "bad.csv", rows))


def test_load_rejects_wrong_columns(tmp_path: Path) -> None:
    header = [*keys()[:-1], "SOMETHING_ELSE", TARGET]
    with pytest.raises(DatasetError, match="Unexpected columns"):
        data.load_raw(_write_csv(tmp_path / "bad.csv", [_row()], header))


def test_load_rejects_short_rows(tmp_path: Path) -> None:
    path = _write_csv(tmp_path / "bad.csv", [_row()])
    path.write_text(path.read_text() + "0,1\n")
    with pytest.raises(DatasetError, match="expected 36"):
        data.load_raw(path)


def test_load_accepts_shuffled_columns(tmp_path: Path) -> None:
    header = [TARGET, *reversed(keys())]
    row = [1] + list(reversed(_row(ones=(0,))[:-1]))
    raw = data.load_raw(_write_csv(tmp_path / "shuffled.csv", [row], header))
    assert raw.y.tolist() == [1]
    assert raw.X[0, 0] == 1 and raw.X[0, 1:].sum() == 0


def test_deduplicate_majority_and_ties() -> None:
    rows = (
        [_row((0,), 1)] * 3  # plain duplicates
        + [_row((1,), 1)] * 2 + [_row((1,), 0)]  # conflict, majority malicious
        + [_row((2,), 1), _row((2,), 0)]  # conflict, tie -> dropped
        + [_row((3,), 0)]
    )
    table = np.array(rows, dtype=np.int8)
    clean = data.deduplicate(RawData(X=table[:, :-1], y=table[:, -1]))
    stats = clean.stats

    assert stats.rows_raw == 9
    assert stats.rows_unique == 6  # distinct (features, label) rows
    assert stats.duplicates_removed == 3
    assert stats.unique_feature_vectors == 4
    assert stats.conflicting_groups == 2
    assert stats.conflicts_resolved_by_majority == 1
    assert stats.conflicts_dropped_as_ties == 1
    assert stats.rows_modeling == 3
    by_vector = {tuple(x): (int(y), int(c)) for x, y, c in zip(clean.X, clean.y, clean.counts,
                                                                strict=True)}
    assert by_vector[tuple(_row((1,))[:-1])] == (1, 3)
    assert tuple(_row((2,))[:-1]) not in by_vector


def test_real_split_has_no_leakage() -> None:
    clean = data.deduplicate(data.load_raw())
    assert clean.stats.rows_unique == 1107
    assert len(np.unique(clean.X, axis=0)) == len(clean.X)
    split = data.split(clean)
    assert data.overlap_fraction(split.X_train, split.X_test) == 0.0
    assert len(split.y_train) + len(split.y_test) == clean.stats.rows_modeling
    # Stratified: class ratio within a percentage point on both sides.
    assert abs(split.y_train.mean() - split.y_test.mean()) < 0.01


def test_overlap_fraction() -> None:
    a = np.array([[0, 1], [1, 1]])
    b = np.array([[0, 1], [0, 0]])
    assert data.overlap_fraction(a, b) == 0.5
    assert data.overlap_fraction(a, b[:0]) == 0.0


def test_feature_prevalence_shape() -> None:
    X = np.array([[1] + [0] * 34, [0] * 35])
    y = np.array([1, 0])
    prevalence = data.feature_prevalence(X, y)
    assert len(prevalence) == 35
    assert prevalence[0]["malicious_rate"] == 1.0
    assert prevalence[0]["benign_rate"] == 0.0
