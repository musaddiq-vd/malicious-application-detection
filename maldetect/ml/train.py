"""Train, compare and export the malware classifier.

Run with ``python -m maldetect.ml.train``. The run is deterministic
(``RANDOM_STATE``) and writes ``models/model.joblib``, ``models/metrics.json``
and the figures in ``reports/figures``.

Method
------
1. Load the CSV, collapse it to one row per distinct feature vector
   (see ``maldetect.ml.data``) and hold out a stratified 20% test set. Because
   every feature vector occurs once, no test row is also a training row.
2. For each model family, grid-search a small hyperparameter grid with
   stratified 5-fold cross-validation on the training portion only.
3. Wrap the best configuration of each family in sigmoid (Platt) calibration
   fitted with internal 5-fold CV, so every model, including the margin-only
   linear SVM, outputs comparable, calibrated probabilities.
4. Choose a decision threshold per model from out-of-fold calibrated
   probabilities on the training portion (never from the test set).
5. Select the winning family, then score every family once on the test set.

Selection criterion
-------------------
The winner is the family with the highest mean cross-validated ROC AUC
(ties broken by F1). ROC AUC measures how well a model ranks malicious above
benign apps independent of any cut-off, which is the right thing to compare
when the cut-off is tuned separately afterwards. The test set plays no part in
the choice, so the reported test metrics are an unbiased estimate for the
shipped model.

Threshold
---------
Missing malware is worse than a false alarm, so the threshold maximises the
F2 score (recall weighted twice as heavily as precision) on out-of-fold
predictions. The search is limited to 0.30-0.70 so that a "malicious" verdict
never contradicts the fixed low/medium/high/critical risk bands.

Caveats worth knowing
---------------------
* Cross-validation scores are those of the best grid point per family, so they
  are slightly optimistic; the held-out test set is the honest number.
* The exported model is fitted on the training portion only, so the test
  metrics in ``metrics.json`` describe exactly the artifact that is shipped.
* ``fit_seconds`` is the wall time for a family's grid search plus calibration.
"""

from __future__ import annotations

import argparse
import json
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.base import BaseEstimator, clone
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    fbeta_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_predict
from sklearn.naive_bayes import BernoulliNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC, LinearSVC

from maldetect import __version__, config
from maldetect.features import FEATURES, slugs
from maldetect.ml import data as data_module
from maldetect.ml.data import RANDOM_STATE, TEST_SIZE, CleanData, RawData, Split

CV_FOLDS = 5
THRESHOLD_GRID = np.round(np.arange(0.30, 0.701, 0.01), 2)
F_BETA = 2.0
MAX_CURVE_POINTS = 100

# The ten columns the original project removed by hand, kept only to reproduce it.
LEGACY_DROPPED_KEYS: tuple[str, ...] = (
    "ACCESS_NETWORK_STATE",
    "BLUETOOTH",
    "ACCESS_WIFI_STATE",
    "BROADCAST_SMS",
    "CALL_PHONE",
    "CALL_PRIVILEGED",
    "CLEAR_APP_CACHE",
    "CLEAR_APP_USER_DATA",
    "CONTROL_LOCATION_UPDATES",
    "INTERNET",
)
LEGACY_RANDOM_STATE = 123


@dataclass(frozen=True)
class Candidate:
    name: str
    estimator: BaseEstimator
    grid: dict[str, list[Any]]


def candidates() -> list[Candidate]:
    """Model families to compare, each with a deliberately small grid."""
    rs = RANDOM_STATE
    return [
        Candidate(
            "Logistic Regression",
            LogisticRegression(max_iter=2000, random_state=rs),
            {"C": [0.03, 0.1, 0.3, 1.0, 3.0, 10.0]},
        ),
        Candidate(
            "Linear SVM",
            LinearSVC(random_state=rs, max_iter=20000),
            {"C": [0.01, 0.03, 0.1, 0.3, 1.0, 3.0]},
        ),
        Candidate(
            "RBF SVM",
            SVC(kernel="rbf", random_state=rs),
            {"C": [0.3, 1.0, 3.0, 10.0, 30.0], "gamma": ["scale", 0.01, 0.03, 0.1]},
        ),
        Candidate(
            "Random Forest",
            RandomForestClassifier(n_estimators=200, random_state=rs, n_jobs=1),
            {"max_features": ["sqrt", 0.3], "min_samples_leaf": [1, 3]},
        ),
        Candidate(
            "Gradient Boosting",
            HistGradientBoostingClassifier(random_state=rs, early_stopping=False),
            {
                "learning_rate": [0.05, 0.1],
                "max_iter": [200],
                "max_leaf_nodes": [7, 15],
                "min_samples_leaf": [5, 20],
            },
        ),
        Candidate(
            "Bernoulli Naive Bayes",
            BernoulliNB(),
            {"alpha": [0.01, 0.1, 0.5, 1.0, 2.0]},
        ),
        Candidate(
            "k-Nearest Neighbors",
            # On 0/1 features the Hamming distance is simply the number of answers that differ.
            KNeighborsClassifier(metric="hamming", algorithm="brute"),
            {"n_neighbors": [3, 5, 9, 15, 25], "weights": ["uniform", "distance"]},
        ),
    ]


def _folds() -> StratifiedKFold:
    return StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)


def _calibrated(estimator: BaseEstimator) -> CalibratedClassifierCV:
    return CalibratedClassifierCV(clone(estimator), method="sigmoid", cv=_folds())


def choose_threshold(y_true: np.ndarray, proba: np.ndarray) -> float:
    """Threshold on the grid with the best F-beta; ties go to the one nearest 0.5."""
    scores = np.array(
        [fbeta_score(y_true, proba >= t, beta=F_BETA, zero_division=0) for t in THRESHOLD_GRID]
    )
    best = np.flatnonzero(np.isclose(scores, scores.max()))
    return float(THRESHOLD_GRID[best[np.argmin(np.abs(THRESHOLD_GRID[best] - 0.5))]])


def classification_metrics(
    y_true: np.ndarray, proba: np.ndarray, threshold: float
) -> dict[str, float]:
    pred = (proba >= threshold).astype(int)
    return {
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, proba)),
        "pr_auc": float(average_precision_score(y_true, proba)),
    }


def _jsonable(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    return value


@dataclass
class FittedCandidate:
    name: str
    params: dict[str, Any]
    cv: dict[str, float]
    threshold: float
    model: CalibratedClassifierCV
    test_proba: np.ndarray
    test: dict[str, float]
    fit_seconds: float

    def to_metrics(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "params": self.params,
            "cv": self.cv,
            "test": self.test,
            "threshold": self.threshold,
            "fit_seconds": round(self.fit_seconds, 3),
        }


def fit_candidate(candidate: Candidate, split: Split) -> FittedCandidate:
    """Grid-search, calibrate, pick a threshold and score one model family."""
    started = time.perf_counter()
    search = GridSearchCV(
        candidate.estimator,
        candidate.grid,
        scoring={"accuracy": "accuracy", "f1": "f1", "roc_auc": "roc_auc"},
        refit=False,
        cv=_folds(),
    )
    search.fit(split.X_train, split.y_train)
    results = search.cv_results_
    # Highest ROC AUC, then highest F1; argmax keeps the first (simplest-listed) grid point.
    order = np.lexsort((-results["mean_test_f1"], -results["mean_test_roc_auc"]))
    best = int(order[0])
    params = {k: _jsonable(v) for k, v in results["params"][best].items()}
    cv = {
        f"{metric}_{stat}": float(results[f"{stat}_test_{metric}"][best])
        for metric in ("accuracy", "f1", "roc_auc")
        for stat in ("mean", "std")
    }

    tuned = clone(candidate.estimator).set_params(**params)
    oof = cross_val_predict(
        _calibrated(tuned), split.X_train, split.y_train, cv=_folds(), method="predict_proba"
    )[:, 1]
    threshold = choose_threshold(split.y_train, oof)

    model = _calibrated(tuned).fit(split.X_train, split.y_train)
    elapsed = time.perf_counter() - started
    test_proba = model.predict_proba(split.X_test)[:, 1]
    return FittedCandidate(
        name=candidate.name,
        params=params,
        cv=cv,
        threshold=threshold,
        model=model,
        test_proba=test_proba,
        test=classification_metrics(split.y_test, test_proba, threshold),
        fit_seconds=elapsed,
    )


def select_best(fitted: list[FittedCandidate]) -> FittedCandidate:
    """Highest mean CV ROC AUC, ties broken by mean CV F1. The test set is not consulted."""
    return max(fitted, key=lambda m: (round(m.cv["roc_auc_mean"], 6), m.cv["f1_mean"]))


def _downsample(*arrays: np.ndarray, limit: int = MAX_CURVE_POINTS) -> list[list[float]]:
    n = len(arrays[0])
    if n <= limit:
        idx = np.arange(n)
    else:
        idx = np.unique(np.linspace(0, n - 1, limit).round().astype(int))
    return [[float(v) for v in np.asarray(a)[idx]] for a in arrays]


def best_model_report(best: FittedCandidate, split: Split) -> dict[str, Any]:
    """Curves, confusion matrix, calibration and permutation importance on the test set."""
    y, proba = split.y_test, best.test_proba
    pred = (proba >= best.threshold).astype(int)
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(y, pred, labels=[0, 1]).ravel())

    fpr, tpr, _ = roc_curve(y, proba)
    fpr_d, tpr_d = _downsample(fpr, tpr)
    precision, recall, _ = precision_recall_curve(y, proba)
    precision_d, recall_d = _downsample(precision, recall)
    frac_pos, mean_pred = calibration_curve(y, proba, n_bins=8, strategy="quantile")

    # Importance = drop in test ROC AUC when one column is shuffled, averaged over repeats.
    importance = permutation_importance(
        best.model,
        split.X_test,
        y,
        scoring="roc_auc",
        n_repeats=10,
        random_state=RANDOM_STATE,
    )
    ranked = sorted(
        (
            {
                "slug": feature.slug,
                "label": feature.label,
                "category": feature.category,
                "importance": float(importance.importances_mean[i]),
                "std": float(importance.importances_std[i]),
            }
            for i, feature in enumerate(FEATURES)
        ),
        key=lambda item: item["importance"],
        reverse=True,
    )
    return {
        "test": best.test,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "roc_curve": {"fpr": fpr_d, "tpr": tpr_d},
        "pr_curve": {"precision": precision_d, "recall": recall_d},
        "calibration": {
            "mean_predicted": [float(v) for v in mean_pred],
            "fraction_positive": [float(v) for v in frac_pos],
        },
        "feature_importance": ranked,
    }


def legacy_baseline(raw: RawData, split: Split) -> dict[str, Any]:
    """Reproduce the original project's evaluation and redo it without leakage.

    The original trained ``SVC(kernel="linear")`` on 25 of the 35 columns after a
    random 80/20 split (``random_state=123``) of the raw CSV, duplicates included,
    and printed test accuracy. ``reported_accuracy`` is that number. The
    ``leak_free_*`` numbers come from the same model and the same 25 columns,
    trained and tested on this pipeline's de-duplicated split.
    """
    from sklearn.model_selection import train_test_split

    keep = [i for i, f in enumerate(FEATURES) if f.key not in LEGACY_DROPPED_KEYS]

    X_tr, X_te, y_tr, y_te = train_test_split(
        raw.X[:, keep], raw.y, test_size=0.20, random_state=LEGACY_RANDOM_STATE
    )
    leaky = SVC(kernel="linear").fit(X_tr, y_tr)
    reported = float(accuracy_score(y_te, leaky.predict(X_te)))
    # A test row "also appears in train" when the identical row (features and label) is there.
    overlap = data_module.overlap_fraction(
        np.column_stack([X_tr, y_tr]), np.column_stack([X_te, y_te])
    )

    clean = SVC(kernel="linear").fit(split.X_train[:, keep], split.y_train)
    pred = clean.predict(split.X_test[:, keep])
    return {
        "description": (
            "Linear SVM, 25 hand-picked features, random 80/20 split on the raw data "
            "with duplicates"
        ),
        "reported_accuracy": reported,
        "leak_free_accuracy": float(accuracy_score(split.y_test, pred)),
        "leak_free_f1": float(f1_score(split.y_test, pred, zero_division=0)),
        "leak_free_precision": float(precision_score(split.y_test, pred, zero_division=0)),
        "leak_free_recall": float(recall_score(split.y_test, pred, zero_division=0)),
        "test_rows_also_in_train_pct": float(overlap),
        "legacy_test_rows": int(len(y_te)),
        "n_features": len(keep),
    }


def dataset_report(raw: RawData, clean: CleanData) -> dict[str, Any]:
    stats = clean.stats
    return {
        "rows_raw": stats.rows_raw,
        "rows_unique": stats.rows_unique,
        "duplicates_removed": stats.duplicates_removed,
        "n_features": len(FEATURES),
        "class_balance_raw": {
            "benign": int((raw.y == 0).sum()),
            "malicious": int((raw.y == 1).sum()),
        },
        "class_balance_unique": {
            "benign": int((clean.y == 0).sum()),
            "malicious": int((clean.y == 1).sum()),
        },
        "unique_feature_vectors": stats.unique_feature_vectors,
        "conflicting_label_groups": stats.conflicting_groups,
        "conflicts_resolved_by_majority": stats.conflicts_resolved_by_majority,
        "conflicts_dropped_as_ties": stats.conflicts_dropped_as_ties,
        "rows_modeling": stats.rows_modeling,
        "feature_prevalence": data_module.feature_prevalence(clean.X, clean.y),
    }


def train(verbose: bool = True) -> dict[str, Any]:
    """Run the whole pipeline in memory; returns ``{"metrics": ..., "bundle": ...}``."""
    raw = data_module.load_raw()
    clean = data_module.deduplicate(raw)
    split = data_module.split(clean)

    def log(message: str) -> None:
        if verbose:
            print(message, flush=True)

    s = clean.stats
    log(
        f"Rows: {s.rows_raw} raw -> {s.rows_unique} unique -> {s.rows_modeling} for modeling "
        f"({s.conflicting_groups} feature vectors had conflicting labels: "
        f"{s.conflicts_resolved_by_majority} majority-resolved, "
        f"{s.conflicts_dropped_as_ties} ties dropped)"
    )
    log(f"Split: {len(split.y_train)} train / {len(split.y_test)} test, {CV_FOLDS}-fold CV\n")
    log(f"{'model':<24}{'cv auc':>9}{'cv f1':>8}{'thr':>6}{'acc':>7}{'prec':>7}{'rec':>7}"
        f"{'f1':>7}{'auc':>7}{'sec':>7}")

    fitted: list[FittedCandidate] = []
    for candidate in candidates():
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fit_candidate(candidate, split)
        fitted.append(result)
        t = result.test
        log(
            f"{result.name:<24}{result.cv['roc_auc_mean']:>9.4f}{result.cv['f1_mean']:>8.4f}"
            f"{result.threshold:>6.2f}{t['accuracy']:>7.3f}{t['precision']:>7.3f}"
            f"{t['recall']:>7.3f}{t['f1']:>7.3f}{t['roc_auc']:>7.3f}{result.fit_seconds:>7.1f}"
        )

    best = select_best(fitted)
    log(f"\nSelected: {best.name} {best.params} (threshold {best.threshold:.2f})")

    legacy = legacy_baseline(raw, split)
    log(
        f"Legacy baseline: reported {legacy['reported_accuracy']:.4f} with "
        f"{legacy['test_rows_also_in_train_pct']:.1%} of test rows also in train; "
        f"leak-free {legacy['leak_free_accuracy']:.4f} (F1 {legacy['leak_free_f1']:.4f})"
    )

    trained_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metrics: dict[str, Any] = {
        "trained_at": trained_at,
        "sklearn_version": sklearn.__version__,
        "dataset": dataset_report(raw, clean),
        "split": {
            "strategy": (
                f"Exact duplicates removed first, then a stratified "
                f"{round((1 - TEST_SIZE) * 100)}/{round(TEST_SIZE * 100)} train/test split; "
                f"stratified {CV_FOLDS}-fold cross-validation on the training portion"
            ),
            "train_rows": int(len(split.y_train)),
            "test_rows": int(len(split.y_test)),
            "cv_folds": CV_FOLDS,
            "random_state": RANDOM_STATE,
        },
        "best_model": best.name,
        "threshold": best.threshold,
        "selection": {
            "criterion": "Highest mean cross-validated ROC AUC (ties broken by F1)",
            "threshold_rule": (
                "Maximises F2 on out-of-fold calibrated probabilities from the training "
                "portion, searched over 0.30-0.70"
            ),
            "calibration": "Sigmoid (Platt) scaling with 5-fold cross-validation",
        },
        "models": [m.to_metrics() for m in fitted],
        "best": best_model_report(best, split),
        "legacy_baseline": legacy,
    }
    bundle = {
        "model": best.model,
        "feature_slugs": slugs(),
        "threshold": best.threshold,
        "model_name": best.name,
        "metadata": {
            "trained_at": trained_at,
            "sklearn_version": sklearn.__version__,
            "maldetect_version": __version__,
            "params": best.params,
            "train_rows": int(len(split.y_train)),
            "random_state": RANDOM_STATE,
            "test_metrics": best.test,
        },
    }
    return {"metrics": metrics, "bundle": bundle}


def save(result: dict[str, Any]) -> None:
    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(result["bundle"], config.MODEL_PATH, compress=3)
    config.METRICS_PATH.write_text(
        json.dumps(result["metrics"], indent=2) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train and export the malware classifier.")
    parser.add_argument("--no-figures", action="store_true", help="skip regenerating figures")
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    args = parser.parse_args(argv)

    started = time.perf_counter()
    result = train(verbose=not args.quiet)
    save(result)
    if not args.quiet:
        print(f"\nWrote {config.MODEL_PATH.relative_to(config.ROOT_DIR)}")
        print(f"Wrote {config.METRICS_PATH.relative_to(config.ROOT_DIR)}")

    if not args.no_figures:
        from maldetect.ml.figures import render_all

        for path in render_all(result["metrics"]):
            if not args.quiet:
                print(f"Wrote {path.relative_to(config.ROOT_DIR)}")
    if not args.quiet:
        print(f"Done in {time.perf_counter() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
