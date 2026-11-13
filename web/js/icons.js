// One small stroke icon set (24px grid, 1.75 stroke, round joins) so every
// glyph in the product shares the same weight and geometry.

import { s } from "./dom.js";

const P = (d) => ["path", { d }];
const C = (cx, cy, r) => ["circle", { cx, cy, r }];
const SHIELD = "M12 3l8 3v6c0 4.8-3.2 8.3-8 10-4.8-1.7-8-5.2-8-10V6z";

const ICONS = {
  shield: [P(SHIELD)],
  "shield-check": [P(SHIELD), P("M8.5 12.2l2.5 2.5 4.5-5")],
  "shield-alert": [P(SHIELD), P("M12 8v4.5"), P("M12 15.8v.2")],
  dashboard: [P("M4 4h7v9H4z"), P("M13 4h7v5h-7z"), P("M13 11h7v9h-7z"), P("M4 15h7v5H4z")],
  scan: [P("M4 8V5a1 1 0 0 1 1-1h3"), P("M16 4h3a1 1 0 0 1 1 1v3"), P("M20 16v3a1 1 0 0 1-1 1h-3"), P("M8 20H5a1 1 0 0 1-1-1v-3"), P("M4 12h16")],
  history: [P("M4 12a8 8 0 1 0 2.6-5.9"), P("M4 4v4.5h4.5"), P("M12 8v4.3l3 1.7")],
  insights: [P("M4 20V4"), P("M4 20h16"), P("M8 16v-4"), P("M12 16V8"), P("M16 16v-6"), P("M20 16v-9")],
  upload: [P("M12 16V4"), P("M7 9l5-5 5 5"), P("M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3")],
  sliders: [P("M4 7h9"), P("M17 7h3"), C(15, 7, 2), P("M4 17h3"), P("M11 17h9"), C(9, 17, 2)],
  sun: [C(12, 12, 4), P("M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4")],
  moon: [P("M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z")],
  logout: [P("M10 4H6a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h4"), P("M15 8l4 4-4 4"), P("M19 12H10")],
  check: [P("M5 12.5l4.5 4.5L19 7.5")],
  x: [P("M6 6l12 12"), P("M18 6L6 18")],
  alert: [P("M12 4l9 15.5H3z"), P("M12 10v4.5"), P("M12 17v.2")],
  info: [C(12, 12, 8.5), P("M12 11v5"), P("M12 7.8v.2")],
  copy: [P("M9 9h10a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1z"), P("M16 9V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3")],
  download: [P("M12 4v11"), P("M7 10.5l5 5 5-5"), P("M4 20h16")],
  settings: [C(12, 12, 3), P("M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8")],
  trash: [P("M4 7h16"), P("M9 7V4.5h6V7"), P("M6.5 7l1 12.5h9l1-12.5"), P("M10 11v5M14 11v5")],
  search: [C(11, 11, 6.5), P("M16 16l4.5 4.5")],
  "chevron-left": [P("M14.5 6l-6 6 6 6")],
  "chevron-right": [P("M9.5 6l6 6-6 6")],
  "chevron-down": [P("M6 9.5l6 6 6-6")],
  "arrow-right": [P("M4 12h15"), P("M13.5 6.5L19 12l-5.5 5.5")],
  "arrow-left": [P("M20 12H5"), P("M10.5 6.5L5 12l5.5 5.5")],
  plus: [P("M12 5v14"), P("M5 12h14")],
  minus: [P("M5 12h14")],
  file: [P("M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"), P("M14 3v5h5")],
  package: [P("M12 3l8 4.5v9L12 21l-8-4.5v-9z"), P("M4 7.5l8 4.5 8-4.5"), P("M12 12v9")],
  eye: [P("M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"), C(12, 12, 2.8)],
  "eye-off": [P("M4 4l16 16"), P("M9.9 5.8A9 9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a15 15 0 0 1-2.9 3.6"), P("M6.3 7.7A15 15 0 0 0 2.5 12S6 18.5 12 18.5a9 9 0 0 0 3.9-.9"), P("M10 10a2.8 2.8 0 0 0 4 4")],
  user: [C(12, 8.5, 3.5), P("M5 20c.6-3.6 3.4-5.5 7-5.5s6.4 1.9 7 5.5")],
  layers: [P("M12 4l9 4.5-9 4.5-9-4.5z"), P("M3 13l9 4.5 9-4.5")],
  target: [C(12, 12, 8.5), C(12, 12, 4.5), P("M12 11.9v.2")],
  database: [P("M5 6.5C5 5 8 4 12 4s7 1 7 2.5S16 9 12 9 5 8 5 6.5z"), P("M5 6.5v11C5 19 8 20 12 20s7-1 7-2.5v-11"), P("M5 12c0 1.5 3 2.5 7 2.5s7-1 7-2.5")],
  bolt: [P("M13 3L5 13.5h6L10 21l8-10.5h-6z")],
};

/** Build an icon. Decorative by default; pass a label to expose it to AT. */
export function icon(name, { size, label } = {}) {
  const parts = ICONS[name] || ICONS.info;
  const svg = s(
    "svg",
    {
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      "stroke-width": 1.75,
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      class: "icon",
      "aria-hidden": label ? null : "true",
      role: label ? "img" : null,
      "aria-label": label || null,
      focusable: "false",
    },
    parts.map(([tag, attrs]) => s(tag, attrs)),
  );
  if (size) {
    svg.setAttribute("width", size);
    svg.setAttribute("height", size);
  }
  return svg;
}

/** The MalDetect mark: a shield with a scan line and a detected dot. */
export function logoMark(size = 28) {
  return s(
    "svg",
    { viewBox: "0 0 32 32", width: size, height: size, fill: "none", "aria-hidden": "true", class: "logo-mark" },
    s("path", {
      d: "M16 3.5 27 7.8v7.8c0 6.2-4.3 10.9-11 13.4C9.3 26.5 5 21.8 5 15.6V7.8z",
      stroke: "var(--accent)",
      "stroke-width": 2.2,
      "stroke-linejoin": "round",
    }),
    s("path", { d: "M10.5 16h11", stroke: "var(--accent)", "stroke-width": 2.2, "stroke-linecap": "round" }),
    s("circle", { cx: 16, cy: 16, r: 2.6, fill: "var(--mal)" }),
  );
}
