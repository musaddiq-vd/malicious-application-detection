"""README figures, rendered from ``models/metrics.json``.

``python -m maldetect.ml.figures`` re-renders every figure from the saved
metrics without retraining; training calls ``render_all`` automatically.
All figures share one light style, are 1600 px wide and use a fixed colour
assignment: benign = blue, malicious = orange, cross-validation = blue,
held-out test = aqua.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

from maldetect import config  # noqa: E402
from maldetect.features import CATEGORIES  # noqa: E402

WIDTH_IN = 10.0
DPI = 160  # 10 in x 160 dpi = 1600 px

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
INK_3 = "#8a8984"
GRID = "#e6e5e1"
BLUE = "#2a78d6"
ORANGE = "#eb6834"
AQUA = "#1baf7a"
NEUTRAL = "#b9b8b2"
SEQUENTIAL = ["#eef4fc", "#c4dbf6", "#8bb8ec", "#4f92de", "#2a78d6", "#1d5aa6"]

BENIGN_COLOR, MALICIOUS_COLOR = BLUE, ORANGE
CV_COLOR, TEST_COLOR = BLUE, AQUA


def _style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "font.family": "DejaVu Sans",
            "font.size": 10.5,
            "text.color": INK,
            "axes.labelcolor": INK_2,
            "axes.edgecolor": GRID,
            "axes.titlesize": 13,
            "axes.titleweight": "bold",
            "axes.titlelocation": "left",
            "axes.titlepad": 12,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": GRID,
            "grid.linewidth": 0.8,
            "xtick.color": INK_2,
            "ytick.color": INK_2,
            "xtick.major.size": 0,
            "ytick.major.size": 0,
            "legend.frameon": False,
            "legend.fontsize": 10,
        }
    )


def _subtitle(ax: Axes, text: str) -> None:
    ax.text(0, 1.012, text, transform=ax.transAxes, color=INK_2, fontsize=10, va="bottom")


def _title(ax: Axes, title: str, subtitle: str | None = None) -> None:
    ax.set_title(title, pad=26 if subtitle else 12)
    if subtitle:
        _subtitle(ax, subtitle)


def _save(fig: Figure, name: str, out_dir: Path, scale: float = 1.0) -> Path:
    """Save at ~1600 px wide; narrower figures pass ``scale`` to keep that pixel width."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    fig.savefig(path, dpi=round(DPI * scale), bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    return path


# --------------------------------------------------------------------------- figures


def model_comparison(metrics: Mapping[str, Any], out_dir: Path) -> Path:
    """Dot plot of ROC AUC and F1 per model: CV mean +- std versus held-out test."""
    models = sorted(metrics["models"], key=lambda m: m["cv"]["roc_auc_mean"])
    names = [m["name"] for m in models]
    best = metrics["best_model"]
    y = np.arange(len(models))

    fig, axes = plt.subplots(1, 2, figsize=(WIDTH_IN, 0.55 * len(models) + 2.2), sharey=True)
    panels = (("roc_auc", "ROC AUC"), ("f1", "F1 score"))
    for ax, (key, label) in zip(axes, panels, strict=True):
        cv_mean = np.array([m["cv"][f"{key}_mean"] for m in models])
        cv_std = np.array([m["cv"][f"{key}_std"] for m in models])
        test = np.array([m["test"][key] for m in models])
        ax.hlines(y, np.minimum(cv_mean, test), np.maximum(cv_mean, test), color=GRID, lw=2)
        ax.errorbar(
            cv_mean, y + 0.0, xerr=cv_std, fmt="o", color=CV_COLOR, ms=8, lw=1.5, capsize=0,
            label="5-fold CV (mean ± sd)", zorder=3,
        )
        ax.scatter(test, y, marker="D", s=52, color=TEST_COLOR, edgecolor=SURFACE,
                   linewidth=1.5, label="Held-out test", zorder=4)
        low = min((cv_mean - cv_std).min(), test.min())
        ax.set_xlim(max(0.0, np.floor(low * 50) / 50 - 0.01), 1.0)
        ax.set_xlabel(label)
        ax.grid(axis="y", visible=False)
        ax.set_title(label, fontsize=11.5, pad=8)
    axes[0].set_yticks(y, [f"{n}  ★" if n == best else n for n in names])
    for tick, name in zip(axes[0].get_yticklabels(), names, strict=True):
        if name == best:
            tick.set_fontweight("bold")
            tick.set_color(INK)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper right", ncol=2, bbox_to_anchor=(0.99, 1.0))
    fig.suptitle("Model comparison", x=0.01, ha="left", fontsize=14, fontweight="bold")
    fig.text(
        0.01, 0.905,
        f"★ selected model ({best}): highest mean CV ROC AUC. "
        f"Test set: {metrics['split']['test_rows']} unseen, de-duplicated apps.",
        color=INK_2, fontsize=10,
    )
    fig.subplots_adjust(left=0.2, right=0.98, top=0.8, bottom=0.12, wspace=0.1)
    return _save(fig, "model_comparison.png", out_dir)


def confusion(metrics: Mapping[str, Any], out_dir: Path) -> Path:
    cm = metrics["best"]["confusion_matrix"]
    grid = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    rows = grid.sum(axis=1, keepdims=True)
    share = np.divide(grid, rows, out=np.zeros_like(grid, dtype=float), where=rows > 0)

    from matplotlib.colors import LinearSegmentedColormap

    cmap = LinearSegmentedColormap.from_list("seq", SEQUENTIAL)
    fig, ax = plt.subplots(figsize=(WIDTH_IN * 0.62, 5.4))
    ax.imshow(share, cmap=cmap, vmin=0, vmax=1)
    names = [["True negatives", "False positives"], ["False negatives", "True positives"]]
    for i in range(2):
        for j in range(2):
            dark = share[i, j] > 0.55
            color = "white" if dark else INK
            ax.text(j, i - 0.08, f"{grid[i, j]}", ha="center", va="center", fontsize=24,
                    fontweight="bold", color=color)
            ax.text(j, i + 0.2, f"{names[i][j]} · {share[i, j]:.1%} of row", ha="center",
                    va="center", fontsize=9.5, color="white" if dark else INK_2)
    ax.set_xticks([0, 1], ["Predicted benign", "Predicted malicious"])
    ax.set_yticks([0, 1], ["Actually benign", "Actually malicious"])
    ax.grid(False)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    # White gaps between cells.
    ax.axhline(0.5, color=SURFACE, lw=4)
    ax.axvline(0.5, color=SURFACE, lw=4)
    _title(
        ax,
        f"Confusion matrix · {metrics['best_model']}",
        f"Held-out test set, decision threshold {metrics['threshold']:.2f}",
    )
    fig.tight_layout()
    return _save(fig, "confusion_matrix.png", out_dir, scale=1.6)


def roc(metrics: Mapping[str, Any], out_dir: Path) -> Path:
    curve = metrics["best"]["roc_curve"]
    auc = metrics["best"]["test"]["roc_auc"]
    fig, ax = plt.subplots(figsize=(WIDTH_IN * 0.62, 5.6))
    ax.plot([0, 1], [0, 1], color=NEUTRAL, lw=1.2, ls=(0, (4, 4)), label="Chance")
    ax.plot(curve["fpr"], curve["tpr"], color=BLUE, lw=2.2, label=f"{metrics['best_model']}")
    ax.fill_between(curve["fpr"], curve["tpr"], color=BLUE, alpha=0.08, step=None)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("False positive rate (benign apps flagged)")
    ax.set_ylabel("True positive rate (malware caught)")
    ax.set_aspect("equal")
    ax.legend(loc="lower right")
    _title(ax, "ROC curve", f"Held-out test set · ROC AUC {auc:.3f}")
    fig.tight_layout()
    return _save(fig, "roc_curve.png", out_dir, scale=1.85)


def pr(metrics: Mapping[str, Any], out_dir: Path) -> Path:
    curve = metrics["best"]["pr_curve"]
    ap = metrics["best"]["test"]["pr_auc"]
    balance = metrics["dataset"]["class_balance_unique"]
    base = balance["malicious"] / max(1, balance["malicious"] + balance["benign"])
    fig, ax = plt.subplots(figsize=(WIDTH_IN * 0.62, 5.6))
    ax.axhline(base, color=NEUTRAL, lw=1.2, ls=(0, (4, 4)), label=f"Chance ({base:.2f})")
    ax.plot(curve["recall"], curve["precision"], color=ORANGE, lw=2.2,
            label=metrics["best_model"])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("Recall (share of malware caught)")
    ax.set_ylabel("Precision (share of alerts that are malware)")
    ax.set_aspect("equal")
    ax.legend(loc="lower left")
    _title(ax, "Precision-recall curve", f"Held-out test set · average precision {ap:.3f}")
    fig.tight_layout()
    return _save(fig, "pr_curve.png", out_dir, scale=1.85)


def importance(metrics: Mapping[str, Any], out_dir: Path, top: int = 15) -> Path:
    items = metrics["best"]["feature_importance"][:top][::-1]
    labels = [f"{i['label']}  ·  {CATEGORIES.get(i['category'], i['category'])}" for i in items]
    values = np.array([i["importance"] for i in items])
    stds = np.array([i["std"] for i in items])
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 0.42 * len(items) + 1.6))
    y = np.arange(len(items))
    ax.barh(y, values, height=0.62, color=BLUE, edgecolor=SURFACE, linewidth=2)
    ax.errorbar(values, y, xerr=stds, fmt="none", ecolor=INK_3, elinewidth=1, capsize=0)
    for yi, v, s in zip(y, values, stds, strict=True):
        ax.text(max(v + s, 0) + values.max() * 0.015, yi, f"{v:.3f}", va="center",
                fontsize=9, color=INK_2)
    ax.set_yticks(y, labels)
    ax.set_xlim(min(0, (values - stds).min() * 1.1), (values + stds).max() * 1.15)
    ax.axvline(0, color=INK_3, lw=0.8)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("Drop in test ROC AUC when the feature is shuffled (mean ± sd, 10 repeats)")
    _title(
        ax,
        f"Top {len(items)} features · permutation importance",
        f"{metrics['best_model']} on the held-out test set",
    )
    fig.tight_layout()
    return _save(fig, "feature_importance.png", out_dir)


def prevalence(metrics: Mapping[str, Any], out_dir: Path) -> Path:
    items = sorted(
        metrics["dataset"]["feature_prevalence"],
        key=lambda i: i["malicious_rate"] - i["benign_rate"],
    )
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 0.3 * len(items) + 1.8))
    y = np.arange(len(items))
    benign = np.array([i["benign_rate"] for i in items])
    malicious = np.array([i["malicious_rate"] for i in items])
    ax.hlines(y, np.minimum(benign, malicious), np.maximum(benign, malicious), color=GRID, lw=3)
    ax.scatter(benign, y, s=46, color=BENIGN_COLOR, edgecolor=SURFACE, linewidth=1.5,
               label="Benign apps", zorder=3)
    ax.scatter(malicious, y, s=46, color=MALICIOUS_COLOR, edgecolor=SURFACE, linewidth=1.5,
               label="Malicious apps", zorder=4)
    ax.set_yticks(y, [i["label"] for i in items], fontsize=9.5)
    ax.set_xlim(-0.02, 1.02)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("Share of apps with the feature")
    ax.legend(loc="lower right", ncol=1, borderpad=1.0)
    balance = metrics["dataset"]["class_balance_unique"]
    _title(
        ax,
        "How often each feature appears",
        f"De-duplicated data: {balance['benign']} benign and {balance['malicious']} malicious "
        "apps; sorted by the gap",
    )
    fig.tight_layout()
    return _save(fig, "feature_prevalence.png", out_dir)


def legacy(metrics: Mapping[str, Any], out_dir: Path) -> Path:
    leg = metrics["legacy_baseline"]
    best = metrics["best"]["test"]
    bars = [
        ("Original script\n(leaky split, as printed)", leg["reported_accuracy"], NEUTRAL),
        ("Original model\nevaluated leak-free", leg["leak_free_accuracy"], BLUE),
        (f"New model\n({metrics['best_model']})", best["accuracy"], AQUA),
    ]
    f1s = [None, leg["leak_free_f1"], best["f1"]]
    fig, ax = plt.subplots(figsize=(WIDTH_IN, 5.4))
    x = np.arange(len(bars))
    ax.bar(x, [b[1] for b in bars], width=0.56, color=[b[2] for b in bars],
           edgecolor=SURFACE, linewidth=2)
    for xi, (_, value, _), f1 in zip(x, bars, f1s, strict=True):
        ax.text(xi, value + 0.015, f"{value:.1%}", ha="center", va="bottom", fontsize=15,
                fontweight="bold")
        if f1 is not None:
            ax.text(xi, value - 0.05, f"F1 {f1:.3f}", ha="center", va="top", fontsize=10,
                    color="white")
    ax.set_xticks(x, [b[0] for b in bars])
    ax.set_ylim(0, 1.12)
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.set_ylabel("Test accuracy")
    ax.grid(axis="x", visible=False)
    _title(
        ax,
        "The original accuracy was measured on rows the model had already seen",
        f"{leg['test_rows_also_in_train_pct']:.0%} of the original test rows also appeared in "
        "its training data; the leak-free bars use a de-duplicated split",
    )
    fig.tight_layout()
    return _save(fig, "legacy_vs_leak_free.png", out_dir)


RENDERERS = (model_comparison, confusion, roc, pr, importance, prevalence, legacy)


def render_all(metrics: Mapping[str, Any], out_dir: Path | None = None) -> list[Path]:
    """Render every figure; returns the written paths."""
    _style()
    out_dir = out_dir or config.FIGURES_DIR
    return [render(metrics, out_dir) for render in RENDERERS]


def main() -> int:
    metrics = json.loads(config.METRICS_PATH.read_text(encoding="utf-8"))
    for path in render_all(metrics):
        print(f"Wrote {path.relative_to(config.ROOT_DIR)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
