// Hand-written SVG charts. Each chart is drawn at the container's real pixel
// width and redrawn on resize, so text never scales down to unreadable sizes.

import { h, s, prefersReducedMotion } from "./dom.js";
import { pct, dayLabel, fixed } from "./format.js";

const observer = typeof ResizeObserver === "function"
  ? new ResizeObserver((entries) => {
      for (const entry of entries) {
        const el = entry.target;
        if (!el.isConnected) {
          observer.unobserve(el);
          continue;
        }
        const width = Math.round(entry.contentRect.width);
        if (width > 0 && width !== el.chartWidth) {
          el.chartWidth = width;
          el.replaceChildren(el.chartDraw(width));
        }
      }
    })
  : null;

/** Create a responsive chart container; draw(width) must return an <svg>. */
export function chart(draw, { label } = {}) {
  const el = h("div", { class: "chart", role: "img", "aria-label": label || "Chart" });
  el.chartDraw = draw;
  if (observer) {
    observer.observe(el);
  } else {
    el.append(draw(600));
  }
  return el;
}

function svgRoot(width, height) {
  return s("svg", { viewBox: `0 0 ${width} ${height}`, width, height, "aria-hidden": "true", focusable: "false" });
}

const clamp01 = (v) => Math.max(0, Math.min(1, Number(v) || 0));

function niceMax(value) {
  if (value <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(value));
  const step = [1, 2, 4, 5, 10].find((m) => m * pow >= value / 4) * pow;
  return Math.ceil(value / step) * step;
}

/* ---------- Stacked daily activity ---------- */
export function activityChart(byDay) {
  const days = Array.isArray(byDay) ? byDay : [];
  const total = days.reduce((sum, d) => sum + d.malicious + d.benign, 0);
  return chart(
    (width) => {
      const height = 220;
      const m = { top: 12, right: 4, bottom: 26, left: 28 };
      const iw = width - m.left - m.right;
      const ih = height - m.top - m.bottom;
      const max = niceMax(Math.max(1, ...days.map((d) => d.malicious + d.benign)));
      const y = (v) => m.top + ih - (v / max) * ih;
      const band = iw / Math.max(1, days.length);
      const bw = Math.max(4, Math.min(22, band * 0.5));
      const svg = svgRoot(width, height);

      for (let i = 0; i <= 4; i += 1) {
        const v = (max / 4) * i;
        svg.append(
          s("line", { class: "grid-line", x1: m.left, x2: width - m.right, y1: y(v), y2: y(v) }),
          s("text", { x: m.left - 8, y: y(v) + 3.5, "text-anchor": "end" }, Number.isInteger(v) ? v : v.toFixed(1)),
        );
      }

      const labelEvery = band < 30 ? 3 : band < 52 ? 2 : 1;
      days.forEach((d, i) => {
        const x = m.left + band * i + (band - bw) / 2;
        const g = s("g", {
          class: "bar-day",
          dataset: { tip: `${dayLabel(d.date)}\nMalicious: ${d.malicious}\nBenign: ${d.benign}` },
        });
        g.append(s("rect", { class: "hit", x: m.left + band * i, y: m.top, width: band, height: ih, rx: 4 }));
        const hb = (d.benign / max) * ih;
        const hm = (d.malicious / max) * ih;
        const gap = d.benign && d.malicious ? 2 : 0;
        if (d.benign) g.append(s("rect", { x, y: y(d.benign), width: bw, height: hb, rx: 2.5, fill: "var(--ben)" }));
        if (d.malicious) {
          g.append(s("rect", { x, y: y(d.benign + d.malicious), width: bw, height: Math.max(1, hm - gap), rx: 2.5, fill: "var(--mal)" }));
        }
        if (!d.benign && !d.malicious) {
          g.append(s("rect", { x, y: m.top + ih - 2, width: bw, height: 2, rx: 1, fill: "var(--border-strong)" }));
        }
        svg.append(g);
        if ((days.length - 1 - i) % labelEvery === 0) {
          svg.append(s("text", { x: x + bw / 2, y: height - 8, "text-anchor": "middle" }, dayLabel(d.date)));
        }
      });
      return svg;
    },
    { label: `Scans per day over the last ${days.length} days, ${total} in total, split by verdict` },
  );
}

/* ---------- Risk gauge ---------- */
const ZONES = [
  { to: 0.25, color: "var(--ben)" },
  { to: 0.5, color: "var(--warn)" },
  { to: 0.8, color: "var(--high)" },
  { to: 1, color: "var(--mal)" },
];

function arcPoint(cx, cy, r, v) {
  const a = Math.PI * (1 - v);
  return [cx + r * Math.cos(a), cy - r * Math.sin(a)];
}

function arcPath(cx, cy, r, from, to) {
  const [x0, y0] = arcPoint(cx, cy, r, from);
  const [x1, y1] = arcPoint(cx, cy, r, to);
  return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 0 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

const LEVEL_COLOR = { low: "var(--ben)", medium: "var(--warn)", high: "var(--high)", critical: "var(--mal)" };

/** Semicircular gauge: probability arc, risk zones and the decision threshold. */
export function gauge({ probability, threshold, riskLevel }) {
  const p = clamp01(probability);
  const t = clamp01(threshold);
  const color = LEVEL_COLOR[riskLevel] || "var(--accent)";
  const W = 300;
  const H = 186;
  const cx = W / 2;
  const cy = 150;
  const r = 112;
  const len = Math.PI * r;

  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true", focusable: "false" });

  // Outer zone ring explains what the score ranges mean.
  let from = 0;
  for (const zone of ZONES) {
    svg.append(s("path", {
      d: arcPath(cx, cy, r + 15, from + 0.006, zone.to - 0.006),
      stroke: zone.color, "stroke-width": 3, "stroke-linecap": "round", fill: "none", opacity: 0.55,
    }));
    from = zone.to;
  }

  svg.append(s("path", { d: arcPath(cx, cy, r, 0, 1), stroke: "var(--surface-3)", "stroke-width": 16, "stroke-linecap": "round", fill: "none" }));
  const value = s("path", {
    d: arcPath(cx, cy, r, 0, 1), stroke: color, "stroke-width": 16, "stroke-linecap": "round", fill: "none",
    "stroke-dasharray": `0 ${len + 20}`, class: "gauge-value",
  });
  svg.append(value);

  // Threshold marker: a tick across the track plus a label outside the ring.
  const [tx0, ty0] = arcPoint(cx, cy, r - 13, t);
  const [tx1, ty1] = arcPoint(cx, cy, r + 13, t);
  svg.append(s("line", { x1: tx0, y1: ty0, x2: tx1, y2: ty1, stroke: "var(--text)", "stroke-width": 2.5, "stroke-linecap": "round" }));
  const [lx, ly] = arcPoint(cx, cy, r + 30, t);
  svg.append(s("text", {
    x: lx, y: ly, class: "gauge-threshold",
    "text-anchor": t < 0.4 ? "end" : t > 0.6 ? "start" : "middle",
  }, `threshold ${pct(t)}`));

  const number = s("text", { x: cx, y: cy - 22, "text-anchor": "middle", class: "gauge-number" }, pct(0));
  svg.append(number, s("text", { x: cx, y: cy + 2, "text-anchor": "middle", class: "gauge-caption" }, "malicious probability"));
  svg.append(
    s("text", { x: cx - r, y: cy + 26, "text-anchor": "middle", class: "gauge-end" }, "0%"),
    s("text", { x: cx + r, y: cy + 26, "text-anchor": "middle", class: "gauge-end" }, "100%"),
  );

  const setTo = (v) => {
    // A zero-length dash with round caps would still paint a dot at 0%.
    value.style.visibility = v <= 0.002 ? "hidden" : "visible";
    value.setAttribute("stroke-dasharray", `${(len * v).toFixed(2)} ${len + 20}`);
    number.textContent = pct(v, p * 100 % 1 !== 0 && v === p ? 1 : 0);
  };

  if (prefersReducedMotion()) {
    setTo(p);
  } else {
    const start = performance.now();
    const duration = 900;
    const step = (now) => {
      const k = Math.min(1, (now - start) / duration);
      const eased = 1 - (1 - k) ** 3;
      setTo(k === 1 ? p : p * eased);
      if (k < 1 && svg.isConnected) requestAnimationFrame(step);
      else setTo(p);
    };
    setTo(0);
    requestAnimationFrame(step);
  }

  return h(
    "div",
    {
      class: "gauge",
      role: "img",
      "aria-label": `Malicious probability ${pct(p, 1)}, decision threshold ${pct(t)}, ${riskLevel || "unknown"} risk`,
    },
    svg,
  );
}

/* ---------- XY line charts (ROC, PR, calibration) ---------- */
export function lineChart({ points, xLabel, yLabel, reference, color = "var(--accent)", markers = false, area = true, label, tip }) {
  const pts = points.filter((p) => Number.isFinite(p[0]) && Number.isFinite(p[1]));
  return chart(
    (width) => {
      const height = Math.round(Math.max(220, Math.min(300, width * 0.78)));
      const m = { top: 10, right: 12, bottom: 40, left: 58 };
      const iw = width - m.left - m.right;
      const ih = height - m.top - m.bottom;
      const x = (v) => m.left + clamp01(v) * iw;
      const y = (v) => m.top + (1 - clamp01(v)) * ih;
      const svg = svgRoot(width, height);

      for (let i = 0; i <= 4; i += 1) {
        const v = i / 4;
        svg.append(
          s("line", { class: "grid-line", x1: m.left, x2: m.left + iw, y1: y(v), y2: y(v) }),
          s("line", { class: "grid-line", x1: x(v), x2: x(v), y1: m.top, y2: m.top + ih }),
          s("text", { x: m.left - 8, y: y(v) + 3.5, "text-anchor": "end" }, v.toFixed(2).replace(/0$/, "")),
          s("text", { x: x(v), y: m.top + ih + 15, "text-anchor": "middle" }, v.toFixed(2).replace(/0$/, "")),
        );
      }
      svg.append(
        s("text", { class: "axis-title", x: m.left + iw / 2, y: height - 6, "text-anchor": "middle" }, xLabel),
        s("text", { class: "axis-title", transform: `translate(13 ${m.top + ih / 2}) rotate(-90)`, "text-anchor": "middle" }, yLabel),
      );

      if (reference) {
        const [[rx0, ry0], [rx1, ry1]] = reference;
        svg.append(s("line", { class: "ref-line", x1: x(rx0), y1: y(ry0), x2: x(rx1), y2: y(ry1) }));
      }

      if (pts.length) {
        const d = pts.map((p, i) => `${i ? "L" : "M"}${x(p[0]).toFixed(1)} ${y(p[1]).toFixed(1)}`).join(" ");
        if (area) {
          const closed = `${d} L${x(pts[pts.length - 1][0]).toFixed(1)} ${y(0)} L${x(pts[0][0]).toFixed(1)} ${y(0)} Z`;
          svg.append(s("path", { d: closed, fill: color, opacity: 0.1 }));
        }
        svg.append(s("path", { d, fill: "none", stroke: color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
        if (markers) {
          for (const p of pts) {
            svg.append(s("circle", {
              cx: x(p[0]), cy: y(p[1]), r: 4, fill: "var(--surface)", stroke: color, "stroke-width": 2,
              dataset: { tip: tip ? tip(p) : `${fixed(p[0], 2)}, ${fixed(p[1], 2)}` },
            }));
          }
        }
      }
      return svg;
    },
    { label },
  );
}

/* ---------- Model comparison: CV mean ± std vs held-out test ---------- */
export function comparisonChart({ models, metric, best }) {
  const rows = models.map((mdl) => ({
    name: mdl.name,
    mean: mdl.cv ? mdl.cv[`${metric}_mean`] : null,
    std: mdl.cv ? mdl.cv[`${metric}_std`] || 0 : 0,
    test: mdl.test ? mdl.test[metric] : null,
  }));
  const values = rows.flatMap((r) => [r.mean !== null ? r.mean - r.std : null, r.test]).filter(Number.isFinite);
  const lo = values.length ? Math.max(0, Math.floor((Math.min(...values) - 0.02) * 20) / 20) : 0;
  const hi = 1;

  return chart(
    (width) => {
      const stacked = width < 460;
      const gutter = stacked ? 4 : Math.min(190, Math.max(150, width * 0.28));
      const rowH = stacked ? 46 : 34;
      const m = { top: 8, right: 14, bottom: 30, left: gutter };
      const iw = width - m.left - m.right;
      const height = m.top + rows.length * rowH + m.bottom;
      const x = (v) => m.left + ((Math.max(lo, Math.min(hi, v)) - lo) / (hi - lo)) * iw;
      const svg = svgRoot(width, height);

      const ticks = 5;
      for (let i = 0; i <= ticks; i += 1) {
        const v = lo + ((hi - lo) / ticks) * i;
        svg.append(
          s("line", { class: "grid-line", x1: x(v), x2: x(v), y1: m.top, y2: height - m.bottom }),
          s("text", { x: x(v), y: height - m.bottom + 16, "text-anchor": i === ticks ? "end" : i === 0 ? "start" : "middle" }, pct(v)),
        );
      }

      rows.forEach((r, i) => {
        const top = m.top + i * rowH;
        const cy = stacked ? top + 32 : top + rowH / 2;
        const isBest = r.name === best;
        const g = s("g", {
          dataset: {
            tip: `${r.name}\nCV mean: ${pct(r.mean, 1)} ± ${pct(r.std, 1)}\nTest: ${pct(r.test, 1)}`,
          },
        });
        g.append(s("rect", { class: "hit", x: 0, y: top, width, height: rowH }));
        g.append(s("text", {
          class: "row-label", x: stacked ? m.left : m.left - 14, y: stacked ? top + 16 : cy + 4,
          "text-anchor": stacked ? "start" : "end", "font-weight": isBest ? 600 : 400,
          style: isBest ? { fill: "var(--accent)" } : null,
        }, r.name));
        g.append(s("line", { x1: m.left, x2: m.left + iw, y1: cy, y2: cy, stroke: "var(--border)", "stroke-width": 1 }));
        if (Number.isFinite(r.mean)) {
          const x0 = x(r.mean - r.std);
          const x1 = x(r.mean + r.std);
          g.append(
            s("line", { x1: x0, x2: x1, y1: cy, y2: cy, stroke: "var(--accent)", "stroke-width": 2 }),
            s("line", { x1: x0, x2: x0, y1: cy - 5, y2: cy + 5, stroke: "var(--accent)", "stroke-width": 2 }),
            s("line", { x1, x2: x1, y1: cy - 5, y2: cy + 5, stroke: "var(--accent)", "stroke-width": 2 }),
            s("circle", { cx: x(r.mean), cy, r: 4.5, fill: "var(--accent)", stroke: "var(--surface)", "stroke-width": 1.5 }),
          );
        }
        if (Number.isFinite(r.test)) {
          const tx = x(r.test);
          g.append(s("rect", {
            x: tx - 4.5, y: cy - 4.5, width: 9, height: 9, fill: "var(--text)", stroke: "var(--surface)", "stroke-width": 1.5,
            transform: `rotate(45 ${tx} ${cy})`,
          }));
        }
        svg.append(g);
      });
      return svg;
    },
    { label: `Model comparison by ${metric}: cross-validation mean with standard deviation, and test score` },
  );
}
