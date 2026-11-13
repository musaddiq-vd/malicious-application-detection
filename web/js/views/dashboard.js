// Dashboard: the user's scanning activity at a glance.

import { api } from "../api.js";
import { h, mount, prefersReducedMotion } from "../dom.js";
import { icon } from "../icons.js";
import { activityChart, donut, sparkline } from "../charts.js";
import { int, pct, relativeTime, dateTime } from "../format.js";
import { appCell, card, errorState, loadingBlock, pageHead, probabilityMeter, skeleton, verdictBadge } from "../ui.js";

/** Animate a number from zero so the tiles feel alive on load. */
function countUp(el, target, format) {
  if (prefersReducedMotion() || !target) {
    el.textContent = format(target);
    return;
  }
  const duration = 800;
  const start = performance.now();
  const tick = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - (1 - t) ** 3;
    if (t < 1 && el.isConnected) {
      el.textContent = format(target * eased);
      requestAnimationFrame(tick);
    } else {
      el.textContent = format(target);
    }
  };
  el.textContent = format(0);
  requestAnimationFrame(tick);
}

function kpi({ label, value, format, note, iconName, tone, trend, share }) {
  const valueEl = h("div", { class: "kpi-value num" });
  countUp(valueEl, value || 0, format);
  let foot = null;
  if (trend) {
    foot = sparkline(trend, { label: `${label} per day over the last 14 days` });
  } else if (share !== undefined) {
    const fill = h("span", { style: { width: "0%" } });
    requestAnimationFrame(() => requestAnimationFrame(() => {
      fill.style.width = `${Math.round(share * 100)}%`;
    }));
    foot = h("div", { class: "kpi-meter", "aria-hidden": "true" }, fill);
  }
  return h(
    "div",
    { class: `kpi ${tone ? `tone-${tone}` : ""}` },
    h("div", { class: "kpi-top" }, h("span", { class: "eyebrow" }, label), h("span", { class: "kpi-icon" }, icon(iconName))),
    valueEl,
    h("div", { class: "kpi-note" }, note),
    foot ? h("div", { class: "kpi-foot" }, foot) : null,
  );
}

function legend(parts, total) {
  return h(
    "dl",
    { class: "split-legend" },
    parts.map((p) =>
      h(
        "div",
        null,
        h("dt", null, h("span", { class: "legend-swatch", style: { "--tone": p.color } }), p.label),
        h("dd", { class: "num" }, int(p.value), h("span", { class: "faint" }, total ? ` · ${pct(p.value / total)}` : "")),
      ),
    ),
  );
}

function verdictDonut(stats) {
  const parts = [
    { label: "Malicious", value: stats.malicious || 0, color: "var(--mal)" },
    { label: "Benign", value: stats.benign || 0, color: "var(--ben)" },
  ];
  const total = parts[0].value + parts[1].value;
  return h(
    "div",
    { class: "donut-row" },
    donut(parts, { value: pct(stats.detection_rate), caption: "flagged", label: parts.map((p) => `${p.label}: ${p.value}`).join(", ") }),
    legend(parts, total),
  );
}

function splitBar(parts) {
  const total = parts.reduce((sum, p) => sum + p.value, 0);
  return h(
    "div",
    { class: "split" },
    h(
      "div",
      { class: "split-bar", role: "img", "aria-label": parts.map((p) => `${p.label}: ${p.value}`).join(", ") },
      total
        ? parts.filter((p) => p.value > 0).map((p) => h("span", { style: { flexGrow: String(p.value), "--tone": p.color }, dataset: { tip: `${p.label}: ${p.value}` } }))
        : h("span", { class: "is-empty", style: { flexGrow: "1" } }),
    ),
    legend(parts, total),
  );
}

function emptyDashboard(user) {
  const steps = [
    ["upload", "Provide an app", "Upload an APK for static analysis, or describe an app by toggling its indicators."],
    ["bolt", "Get a risk score", "The model returns a calibrated malicious probability and a verdict in seconds."],
    ["insights", "Read the explanation", "See which permissions and API calls drove the score, feature by feature."],
  ];
  return h(
    "div",
    { class: "page" },
    pageHead({ eyebrow: "Dashboard", title: `Welcome, ${(user.full_name || user.username).split(" ")[0]}`, sub: "You have not scanned anything yet. Your activity and trends will appear here." }),
    h(
      "section",
      { class: "card hero-empty" },
      h(
        "div",
        { class: "hero-empty-text" },
        h("div", { class: "eyebrow" }, "Get started"),
        h("h2", null, "Run your first scan"),
        h("p", { class: "muted" }, "Check an Android app for malicious behaviour. Start with a real APK, or try one of the built-in example profiles to see how the model reasons."),
        h(
          "div",
          { class: "hero-empty-actions" },
          h("a", { class: "btn btn-primary btn-lg", href: "#/scan" }, icon("upload"), "Upload an APK"),
          h("a", { class: "btn btn-lg", href: "#/scan?mode=manual" }, icon("sliders"), "Build a manual profile"),
        ),
      ),
      h(
        "ol",
        { class: "steps" },
        steps.map(([ic, title, text], i) =>
          h("li", null, h("span", { class: "step-num num" }, `0${i + 1}`), h("span", { class: "step-icon" }, icon(ic)), h("div", null, h("strong", null, title), h("span", null, text))),
        ),
      ),
    ),
  );
}

function recentTable(recent) {
  return h(
    "div",
    { class: "table-wrap" },
    h(
      "table",
      { class: "table table-recent" },
      h("thead", null, h("tr", null, h("th", null, "App"), h("th", null, "Verdict"), h("th", { class: "t-right" }, "Risk"), h("th", { class: "t-right col-when" }, "When"))),
      h(
        "tbody",
        null,
        recent.map((scan) => {
          const row = h(
            "tr",
            { class: "is-clickable" },
            h("td", { class: "cell-app" }, appCell(scan)),
            h("td", null, verdictBadge(scan.verdict)),
            h("td", { class: "t-right" }, probabilityMeter(scan.probability, scan.risk_level)),
            h("td", { class: "t-right faint num col-when", title: dateTime(scan.created_at) }, relativeTime(scan.created_at)),
          );
          row.addEventListener("click", (e) => {
            if (!e.target.closest("a, button")) window.location.hash = `#/scans/${scan.id}`;
          });
          return row;
        }),
      ),
    ),
  );
}

function filled(stats) {
  const total = stats.total_scans || 0;
  const maxIndicator = Math.max(1, ...(stats.top_indicators || []).map((i) => i.count));
  const source = stats.by_source || {};
  const days = stats.by_day || [];

  return h(
    "div",
    { class: "page" },
    pageHead({
      eyebrow: "Dashboard",
      title: "Overview",
      sub: "Your scanning activity and what the model has been finding.",
      actions: h("a", { class: "btn btn-primary", href: "#/scan" }, icon("plus"), "New scan"),
    }),
    h(
      "div",
      { class: "kpi-grid" },
      kpi({ label: "Total scans", value: total, format: int, note: "All time", iconName: "layers", trend: days.map((d) => d.malicious + d.benign) }),
      kpi({ label: "Malicious", value: stats.malicious, format: int, note: "Flagged by the model", iconName: "shield-alert", tone: "malicious", trend: days.map((d) => d.malicious) }),
      kpi({ label: "Benign", value: stats.benign, format: int, note: "Below the threshold", iconName: "shield-check", tone: "benign", trend: days.map((d) => d.benign) }),
      kpi({ label: "Detection rate", value: stats.detection_rate, format: pct, note: "Share of scans flagged", iconName: "target", tone: "high", share: stats.detection_rate || 0 }),
      kpi({ label: "Average risk", value: stats.avg_probability, format: pct, note: "Mean malicious probability", iconName: "insights", share: stats.avg_probability || 0 }),
    ),
    h(
      "div",
      { class: "grid grid-2-1" },
      card({
        title: "Scan activity",
        sub: "Scans per day over the last 14 days",
        aside: h(
          "div",
          { class: "legend" },
          h("span", { class: "legend-item" }, h("span", { class: "legend-swatch", style: { "--tone": "var(--mal)" } }), "Malicious"),
          h("span", { class: "legend-item" }, h("span", { class: "legend-swatch", style: { "--tone": "var(--ben)" } }), "Benign"),
        ),
        body: activityChart(stats.by_day),
      }),
      h(
        "div",
        { class: "stack" },
        card({
          title: "Verdict split",
          body: verdictDonut(stats),
        }),
        card({
          title: "Scan source",
          body: splitBar([
            { label: "APK upload", value: source.apk || 0, color: "var(--accent)" },
            { label: "Manual profile", value: source.manual || 0, color: "var(--text-3)" },
          ]),
        }),
      ),
    ),
    h(
      "div",
      { class: "grid grid-1-1" },
      card({
        title: "Top malicious indicators",
        sub: "Features most often present in your malicious scans",
        body: (stats.top_indicators || []).length
          ? h(
              "div",
              { class: "bars" },
              stats.top_indicators.map((ind) =>
                h(
                  "div",
                  { class: "bar-row tone-malicious" },
                  h("span", { class: "bar-label truncate" }, ind.label),
                  h("span", { class: "bar-value num" }, `${int(ind.count)} ${ind.count === 1 ? "scan" : "scans"}`),
                  h("div", { class: "bar-track" }, h("div", { class: "bar-fill", style: { width: `${(ind.count / maxIndicator) * 100}%` } })),
                ),
              ),
            )
          : h("p", { class: "muted note-empty" }, "No malicious scans yet, so there are no indicators to rank."),
      }),
      card({
        title: "Recent scans",
        aside: h("a", { class: "card-link", href: "#/history" }, "View all", icon("arrow-right")),
        flush: true,
        body: recentTable(stats.recent || []),
      }),
    ),
  );
}

export function dashboardView({ user }) {
  const root = h("div", { class: "view" });

  const load = async () => {
    mount(
      root,
      h(
        "div",
        { class: "page" },
        pageHead({ eyebrow: "Dashboard", title: "Overview" }),
        loadingBlock(
          h("div", { class: "kpi-grid" }, [1, 2, 3, 4, 5].map(() => skeleton("sk-tile"))),
          h("div", { class: "grid grid-2-1" }, skeleton("sk-tall"), skeleton("sk-tall")),
        ),
      ),
    );
    try {
      const stats = await api.stats();
      mount(root, stats.total_scans ? filled(stats) : emptyDashboard(user));
    } catch (err) {
      if (err.status === 401) return;
      mount(root, h("div", { class: "page" }, pageHead({ eyebrow: "Dashboard", title: "Overview" }), errorState(err, load)));
    }
  };
  load();
  return root;
}
