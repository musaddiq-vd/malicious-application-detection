// Model insights: how the classifier was evaluated and how far to trust it.

import { api } from "../api.js";
import { h, mount } from "../dom.js";
import { icon } from "../icons.js";
import { comparisonChart, lineChart } from "../charts.js";
import { dateShort, fixed, int, pct } from "../format.js";
import { card, emptyState, errorState, loadingBlock, pageHead, skeleton } from "../ui.js";

const HEADLINE = [
  ["accuracy", "Accuracy", "Share of all test apps classified correctly"],
  ["precision", "Precision", "Of the apps flagged malicious, how many really are"],
  ["recall", "Recall", "Of the malicious apps, how many were caught"],
  ["f1", "F1 score", "Balance of precision and recall"],
  ["roc_auc", "ROC AUC", "Ranking quality across every threshold"],
  ["pr_auc", "PR AUC", "Precision–recall area for the malicious class"],
];

const COMPARE_METRICS = [
  { id: "accuracy", label: "Accuracy" },
  { id: "f1", label: "F1" },
  { id: "roc_auc", label: "ROC AUC" },
];

function zip(xs, ys) {
  const a = Array.isArray(xs) ? xs : [];
  const b = Array.isArray(ys) ? ys : [];
  return a.slice(0, Math.min(a.length, b.length)).map((x, i) => [x, b[i]]);
}

function legendItem(label, cls, tone) {
  return h("span", { class: "legend-item" }, h("span", { class: `legend-swatch ${cls || ""}`, style: tone ? { "--tone": tone } : null }), label);
}

function headline(m) {
  const test = (m.best && m.best.test) || {};
  return h(
    "div",
    { class: "metric-grid" },
    HEADLINE.map(([key, label, note]) =>
      h("div", { class: "kpi kpi-metric" }, h("span", { class: "eyebrow" }, label), h("div", { class: "kpi-value num" }, pct(test[key], 1)), h("div", { class: "kpi-note" }, note)),
    ),
  );
}

/* ---------- Legacy baseline: the data-leakage story ---------- */
function legacyCard(m) {
  const lb = m.legacy_baseline;
  if (!lb) return null;
  const ds = m.dataset || {};
  const bestAcc = m.best && m.best.test ? m.best.test.accuracy : null;
  const drop = Number.isFinite(lb.reported_accuracy) && Number.isFinite(lb.leak_free_accuracy) ? lb.reported_accuracy - lb.leak_free_accuracy : null;

  const bars = [
    { label: "Legacy model, as originally reported", note: "Random split on raw data with duplicates", value: lb.reported_accuracy, cls: "is-leaky", tag: "Inflated by leakage" },
    { label: "Same legacy model, leak-free", note: "Evaluated on the de-duplicated split", value: lb.leak_free_accuracy, cls: "is-honest", tag: "Honest" },
    { label: `Current model (${m.best_model || "best"})`, note: "Held-out test set, de-duplicated", value: bestAcc, cls: "is-current", tag: "Honest" },
  ];

  return h(
    "section",
    { class: "card legacy" },
    h(
      "div",
      { class: "legacy-text" },
      h("div", { class: "eyebrow" }, "Evaluation integrity"),
      h("h2", null, "Legacy baseline vs leak-free evaluation"),
      h(
        "p",
        null,
        "The original version of this project reported ",
        h("strong", { class: "num" }, pct(lb.reported_accuracy, 1)),
        " accuracy. That number was too good to be true: the dataset holds ",
        h("strong", { class: "num" }, int(ds.rows_raw)),
        " rows but only ",
        h("strong", { class: "num" }, int(ds.rows_unique)),
        " distinct feature profiles, and it was split at random without removing duplicates.",
      ),
      h(
        "p",
        null,
        "As a result, ",
        h("strong", { class: "num" }, pct(lb.test_rows_also_in_train_pct, 1)),
        " of the test rows were exact copies of rows the model had already trained on. It was being graded largely on answers it had memorised.",
      ),
      h(
        "p",
        null,
        "Re-evaluated on de-duplicated data, the same legacy model scores ",
        h("strong", { class: "num" }, pct(lb.leak_free_accuracy, 1)),
        " accuracy",
        Number.isFinite(lb.leak_free_f1) ? [" (F1 ", h("span", { class: "num" }, pct(lb.leak_free_f1, 1)), ")"] : null,
        drop !== null ? [", ", h("strong", { class: "num" }, `${(drop * 100).toFixed(1)} points`), drop >= 0 ? " lower" : " different"] : null,
        ". Every metric on this page comes from the leak-free protocol: duplicates are removed before splitting, so the test set contains only profiles the model has never seen.",
      ),
      lb.description ? h("p", { class: "legacy-desc faint" }, h("span", { class: "eyebrow" }, "Legacy method"), " ", lb.description) : null,
    ),
    h(
      "div",
      { class: "legacy-chart" },
      h("div", { class: "eyebrow" }, "Accuracy"),
      bars.map((b) =>
        h(
          "div",
          { class: `legacy-bar ${b.cls}` },
          h("div", { class: "legacy-bar-head" }, h("div", null, h("strong", null, b.label), h("span", { class: "faint" }, b.note)), h("span", { class: "legacy-bar-value num" }, pct(b.value, 1))),
          h("div", { class: "legacy-bar-track", role: "img", "aria-label": `${b.label}: ${pct(b.value, 1)}` }, h("div", { class: "legacy-bar-fill", style: { width: `${Math.max(0, Math.min(1, b.value || 0)) * 100}%` } })),
          h("span", { class: "legacy-tag" }, icon(b.cls === "is-leaky" ? "alert" : "check"), b.tag),
        ),
      ),
      h(
        "div",
        { class: "legacy-stat" },
        h("span", { class: "legacy-stat-num num" }, pct(lb.test_rows_also_in_train_pct, 1)),
        h("span", null, "of legacy test rows also appeared in the training set"),
      ),
    ),
  );
}

/* ---------- Dataset ---------- */
function balanceBar(title, balance) {
  const ben = (balance && balance.benign) || 0;
  const mal = (balance && balance.malicious) || 0;
  const total = ben + mal;
  return h(
    "div",
    { class: "balance" },
    h("div", { class: "balance-head" }, h("span", null, title), h("span", { class: "faint num" }, `${int(total)} rows`)),
    h(
      "div",
      { class: "split-bar", role: "img", "aria-label": `${title}: ${int(ben)} benign, ${int(mal)} malicious` },
      total
        ? [
            h("span", { style: { flexGrow: String(ben), "--tone": "var(--ben)" }, dataset: { tip: `Benign: ${int(ben)}` } }),
            h("span", { style: { flexGrow: String(mal), "--tone": "var(--mal)" }, dataset: { tip: `Malicious: ${int(mal)}` } }),
          ]
        : h("span", { class: "is-empty", style: { flexGrow: "1" } }),
    ),
    h(
      "div",
      { class: "balance-legend num" },
      h("span", null, h("span", { class: "legend-swatch", style: { "--tone": "var(--ben)" } }), `Benign ${int(ben)} · ${total ? pct(ben / total) : "–"}`),
      h("span", null, h("span", { class: "legend-swatch", style: { "--tone": "var(--mal)" } }), `Malicious ${int(mal)} · ${total ? pct(mal / total) : "–"}`),
    ),
  );
}

function datasetCard(m) {
  const ds = m.dataset || {};
  const split = m.split || {};
  const facts = [
    ["Raw rows", int(ds.rows_raw)],
    ["Unique rows", int(ds.rows_unique)],
    ["Duplicates removed", int(ds.duplicates_removed)],
    ["Features", int(ds.n_features)],
    ["Training rows", int(split.train_rows)],
    ["Test rows", int(split.test_rows)],
    ["CV folds", int(split.cv_folds)],
    ["Random seed", split.random_state ?? "–"],
  ];
  const dupShare = ds.rows_raw ? ds.duplicates_removed / ds.rows_raw : null;
  return card({
    title: "Dataset and protocol",
    sub: dupShare !== null ? `${pct(dupShare)} of the raw rows were exact duplicates and were removed before training.` : null,
    body: h(
      "div",
      { class: "dataset" },
      h("dl", { class: "stat-grid" }, facts.map(([k, v]) => h("div", null, h("dt", null, k), h("dd", { class: "num" }, v)))),
      h("div", { class: "dataset-balance" }, balanceBar("Class balance, raw", ds.class_balance_raw), balanceBar("Class balance, de-duplicated", ds.class_balance_unique)),
      split.strategy ? h("p", { class: "dataset-strategy" }, h("span", { class: "eyebrow" }, "Split strategy"), h("span", null, split.strategy)) : null,
    ),
  });
}

/* ---------- Model comparison ---------- */
function comparisonCard(m) {
  const models = Array.isArray(m.models) ? m.models : [];
  if (!models.length) return null;
  let metric = "f1";
  const chartSlot = h("div");
  const buttons = COMPARE_METRICS.map((cm) => {
    const btn = h("button", { type: "button", class: "seg-btn", "aria-pressed": String(cm.id === metric) }, cm.label);
    btn.addEventListener("click", () => {
      metric = cm.id;
      buttons.forEach((b, i) => b.setAttribute("aria-pressed", String(COMPARE_METRICS[i].id === metric)));
      paint();
    });
    return btn;
  });
  const paint = () => mount(chartSlot, comparisonChart({ models, metric, best: m.best_model }));
  paint();

  const pm = (mean, std) => (Number.isFinite(mean) ? [fixed(mean), h("span", { class: "faint" }, ` ± ${fixed(std || 0)}`)] : "–");
  const table = h(
    "div",
    { class: "table-wrap" },
    h(
      "table",
      { class: "table table-models" },
      h(
        "thead",
        null,
        h(
          "tr",
          null,
          h("th", null, "Model"),
          ["CV accuracy", "CV F1", "CV ROC AUC", "Test acc.", "Precision", "Recall", "F1", "ROC AUC", "PR AUC", "Fit time"].map((t) => h("th", { class: "t-right" }, t)),
        ),
      ),
      h(
        "tbody",
        null,
        models.map((mdl) => {
          const cv = mdl.cv || {};
          const test = mdl.test || {};
          const isBest = mdl.name === m.best_model;
          return h(
            "tr",
            { class: isBest ? "is-best" : null },
            h("td", { class: "model-name" }, h("strong", null, mdl.name), isBest ? h("span", { class: "badge badge-accent" }, icon("check"), "Selected") : null),
            h("td", { class: "t-right num" }, pm(cv.accuracy_mean, cv.accuracy_std)),
            h("td", { class: "t-right num" }, pm(cv.f1_mean, cv.f1_std)),
            h("td", { class: "t-right num" }, pm(cv.roc_auc_mean, cv.roc_auc_std)),
            ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc"].map((k) => h("td", { class: "t-right num" }, fixed(test[k]))),
            h("td", { class: "t-right num faint" }, Number.isFinite(mdl.fit_seconds) ? `${mdl.fit_seconds.toFixed(2)} s` : "–"),
          );
        }),
      ),
    ),
  );

  return h(
    "section",
    { class: "card" },
    h(
      "div",
      { class: "card-head card-head-wrap" },
      h("div", null, h("h2", { class: "card-title" }, "Model comparison"), h("p", { class: "card-sub" }, `${models.length} candidates, ${int((m.split || {}).cv_folds)}-fold cross-validation on the training set, then one held-out test.`)),
      h("div", { class: "seg", role: "group", "aria-label": "Metric" }, buttons),
    ),
    h(
      "div",
      { class: "card-body" },
      h("div", { class: "legend compare-legend" }, legendItem("CV mean ± 1 std", "is-line", "var(--accent)"), legendItem("Held-out test", "is-diamond", "var(--text)")),
      chartSlot,
    ),
    h("div", { class: "card-divider" }),
    table,
  );
}

/* ---------- Confusion matrix ---------- */
function confusionCard(m) {
  const cm = (m.best && m.best.confusion_matrix) || {};
  const tn = cm.tn || 0;
  const fp = cm.fp || 0;
  const fn = cm.fn || 0;
  const tp = cm.tp || 0;
  const total = tn + fp + fn + tp;
  const max = Math.max(1, tn, fp, fn, tp);
  const cell = (label, value, rowTotal, good) =>
    h(
      "div",
      { class: `cm-cell ${good ? "is-good" : "is-bad"}`, style: { "--w": String(0.06 + 0.3 * (value / max)) }, role: "cell" },
      h("span", { class: "eyebrow" }, label),
      h("strong", { class: "num" }, int(value)),
      h("span", { class: "faint num" }, rowTotal ? `${pct(value / rowTotal, 1)} of row` : "–"),
    );
  return card({
    title: "Confusion matrix",
    sub: `${m.best_model || "Best model"} on ${int(total)} held-out test apps at threshold ${fixed(m.threshold, 2)}`,
    body: h(
      "div",
      { class: "cm", role: "table", "aria-label": "Confusion matrix" },
      h("div", { class: "cm-corner", "aria-hidden": "true" }),
      h("div", { class: "cm-col-head" }, "Predicted benign"),
      h("div", { class: "cm-col-head" }, "Predicted malicious"),
      h("div", { class: "cm-row-head" }, h("span", null, "Actual benign")),
      cell("True negative", tn, tn + fp, true),
      cell("False positive", fp, tn + fp, false),
      h("div", { class: "cm-row-head" }, h("span", null, "Actual malicious")),
      cell("False negative", fn, fn + tp, false),
      cell("True positive", tp, fn + tp, true),
    ),
  });
}

/* ---------- Feature lists ---------- */
function expandable(items, renderRow, limit, noun) {
  const list = h("div", { class: "bars" });
  let expanded = false;
  const btn = h("button", { type: "button", class: "btn btn-sm" });
  const paint = () => {
    mount(list, (expanded ? items : items.slice(0, limit)).map(renderRow));
    btn.textContent = expanded ? `Show top ${limit}` : `Show all ${items.length} ${noun}`;
    btn.setAttribute("aria-expanded", String(expanded));
  };
  btn.addEventListener("click", () => {
    expanded = !expanded;
    paint();
  });
  paint();
  return [list, items.length > limit ? h("div", { class: "contrib-more" }, btn) : null];
}

function importanceCard(m) {
  const items = (m.best && Array.isArray(m.best.feature_importance) ? m.best.feature_importance : []).slice();
  if (!items.length) return null;
  const max = Math.max(...items.map((f) => (f.importance || 0) + (f.std || 0)), 1e-9);
  return card({
    title: "Permutation feature importance",
    sub: "Drop in test score when one feature is shuffled. Whiskers show ± 1 standard deviation across repeats.",
    body: expandable(
      items,
      (f) => {
        const lo = Math.max(0, (f.importance - (f.std || 0)) / max);
        const hi = Math.min(1, (f.importance + (f.std || 0)) / max);
        return h(
          "div",
          { class: "bar-row", dataset: { tip: `${f.label}\nImportance: ${fixed(f.importance, 4)} ± ${fixed(f.std, 4)}` } },
          h("span", { class: "bar-label truncate" }, f.label),
          h("span", { class: "bar-value num" }, fixed(f.importance, 3)),
          h(
            "div",
            { class: "bar-track" },
            h("div", { class: "bar-fill", style: { width: `${Math.max(0, f.importance / max) * 100}%` } }),
            f.std ? h("div", { class: "bar-err", style: { left: `${lo * 100}%`, width: `${Math.max(0, hi - lo) * 100}%` } }) : null,
          ),
        );
      },
      12,
      "features",
    ),
  });
}

function prevalenceCard(m) {
  const items = ((m.dataset && m.dataset.feature_prevalence) || []).slice().sort((a, b) => Math.abs(b.malicious_rate - b.benign_rate) - Math.abs(a.malicious_rate - a.benign_rate));
  if (!items.length) return null;
  return card({
    title: "Feature prevalence by class",
    sub: "How often each feature appears in benign and malicious apps, sorted by the size of the gap.",
    aside: h("div", { class: "legend" }, legendItem("Malicious", "", "var(--mal)"), legendItem("Benign", "", "var(--ben)")),
    body: expandable(
      items,
      (f) =>
        h(
          "div",
          { class: "prev-row", dataset: { tip: `${f.label}\nMalicious apps: ${pct(f.malicious_rate, 1)}\nBenign apps: ${pct(f.benign_rate, 1)}` } },
          h("span", { class: "bar-label truncate" }, f.label),
          h(
            "div",
            { class: "prev-bars" },
            h("div", { class: "prev-line" }, h("div", { class: "bar-track" }, h("div", { class: "bar-fill", style: { width: `${(f.malicious_rate || 0) * 100}%`, "--tone": "var(--mal)" } })), h("span", { class: "bar-value num" }, pct(f.malicious_rate))),
            h("div", { class: "prev-line" }, h("div", { class: "bar-track" }, h("div", { class: "bar-fill", style: { width: `${(f.benign_rate || 0) * 100}%`, "--tone": "var(--ben)" } })), h("span", { class: "bar-value num" }, pct(f.benign_rate))),
          ),
        ),
      12,
      "features",
    ),
  });
}

function curveCards(m) {
  const best = m.best || {};
  const roc = best.roc_curve || {};
  const pr = best.pr_curve || {};
  const cal = best.calibration || {};
  const test = best.test || {};
  const uniq = (m.dataset && m.dataset.class_balance_unique) || {};
  const baseRate = uniq.benign + uniq.malicious > 0 ? uniq.malicious / (uniq.benign + uniq.malicious) : null;

  return [
    card({
      title: "ROC curve",
      sub: `AUC ${fixed(test.roc_auc)}. The closer to the top-left corner, the better.`,
      body: [
        lineChart({ points: zip(roc.fpr, roc.tpr), xLabel: "False positive rate", yLabel: "True positive rate", reference: [[0, 0], [1, 1]], label: `ROC curve, area under curve ${fixed(test.roc_auc)}` }),
        h("div", { class: "legend chart-legend" }, legendItem(m.best_model || "Model", "is-line", "var(--accent)"), legendItem("Random guess", "is-line is-dashed")),
      ],
    }),
    card({
      title: "Precision–recall curve",
      sub: `Average precision ${fixed(test.pr_auc)}. Shows the cost of catching more malware.`,
      body: [
        lineChart({
          points: zip(pr.recall, pr.precision).sort((a, b) => a[0] - b[0]),
          xLabel: "Recall",
          yLabel: "Precision",
          reference: baseRate !== null ? [[0, baseRate], [1, baseRate]] : null,
          label: `Precision-recall curve, average precision ${fixed(test.pr_auc)}`,
        }),
        h("div", { class: "legend chart-legend" }, legendItem(m.best_model || "Model", "is-line", "var(--accent)"), baseRate !== null ? legendItem(`Malicious base rate (${pct(baseRate)})`, "is-line is-dashed") : null),
      ],
    }),
    card({
      title: "Calibration",
      sub: "When the model says 80%, is it right about 80% of the time?",
      body: [
        lineChart({
          points: zip(cal.mean_predicted, cal.fraction_positive),
          xLabel: "Predicted probability",
          yLabel: "Observed malicious share",
          reference: [[0, 0], [1, 1]],
          markers: true,
          area: false,
          label: "Calibration plot: predicted probability against observed share of malicious apps",
          tip: (p) => `Predicted ${pct(p[0])}\nObserved ${pct(p[1])}`,
        }),
        h("div", { class: "legend chart-legend" }, legendItem(m.best_model || "Model", "is-line", "var(--accent)"), legendItem("Perfect calibration", "is-line is-dashed")),
      ],
    }),
  ];
}

function insightsPage(m) {
  const sub = [
    m.best_model ? `Selected model: ${m.best_model}` : null,
    m.trained_at ? `trained ${dateShort(m.trained_at)}` : null,
    m.sklearn_version ? `scikit-learn ${m.sklearn_version}` : null,
  ].filter(Boolean).join(" · ");

  return h(
    "div",
    { class: "page page-insights" },
    pageHead({ eyebrow: "Model insights", title: "How good is the model?", sub }),
    h("h2", { class: "section-title" }, "Held-out test performance", h("span", { class: "faint" }, m.best_model ? ` · ${m.best_model}` : "")),
    headline(m),
    legacyCard(m),
    comparisonCard(m),
    h("div", { class: "grid grid-1-1" }, confusionCard(m), datasetCard(m)),
    h("div", { class: "grid grid-3" }, curveCards(m)),
    h("div", { class: "grid grid-1-1" }, importanceCard(m), prevalenceCard(m)),
  );
}

export function insightsView() {
  const root = h("div", { class: "view" });
  const load = async () => {
    mount(
      root,
      h(
        "div",
        { class: "page page-insights" },
        pageHead({ eyebrow: "Model insights", title: "How good is the model?" }),
        loadingBlock(h("div", { class: "metric-grid" }, Array.from({ length: 6 }, () => skeleton("sk-tile"))), skeleton("sk-tall", { marginTop: "24px" }), skeleton("sk-tall", { marginTop: "24px" })),
      ),
    );
    try {
      const metrics = await api.metrics();
      mount(root, insightsPage(metrics || {}));
    } catch (err) {
      if (err.status === 401) return;
      const head = pageHead({ eyebrow: "Model insights", title: "How good is the model?" });
      if (err.status === 404 || err.status === 503) {
        mount(
          root,
          h(
            "div",
            { class: "page" },
            head,
            h("div", { class: "card" }, emptyState({ iconName: "insights", title: "No metrics available yet", text: "Metrics are written when the model is trained. Train the model on the server, then reload this page." })),
          ),
        );
        return;
      }
      mount(root, h("div", { class: "page" }, head, errorState(err, load)));
    }
  };
  load();
  return root;
}
