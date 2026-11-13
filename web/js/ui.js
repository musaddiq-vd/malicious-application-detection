// Shared UI primitives: toasts, tooltip, confirm dialog, badges, skeletons, theme.

import { h, mount } from "./dom.js";
import { icon } from "./icons.js";
import { pct, titleCase } from "./format.js";

/* ---------- Theme ---------- */
const THEME_KEY = "maldetect-theme";
const themeListeners = new Set();

export function getTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* storage unavailable: the choice simply lasts for this page view */
  }
  themeListeners.forEach((fn) => fn(theme));
}

export function themeToggle({ withLabel = false } = {}) {
  const btn = h("button", { type: "button", class: withLabel ? "btn btn-ghost theme-toggle" : "btn btn-ghost btn-icon theme-toggle" });
  const paint = () => {
    const next = getTheme() === "dark" ? "light" : "dark";
    btn.setAttribute("aria-label", `Switch to ${next} theme`);
    btn.dataset.tip = withLabel ? "" : `Switch to ${next} theme`;
    mount(btn, icon(next === "light" ? "sun" : "moon"), withLabel ? h("span", null, `${titleCase(next)} theme`) : null);
  };
  btn.addEventListener("click", () => setTheme(getTheme() === "dark" ? "light" : "dark"));
  themeListeners.add(paint);
  paint();
  return btn;
}

/* ---------- Toasts ---------- */
export function toast(message, { type = "info", timeout = 4500 } = {}) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const iconName = type === "success" ? "check" : type === "error" ? "alert" : "info";
  const el = h(
    "div",
    { class: `toast toast-${type}`, role: type === "error" ? "alert" : "status" },
    icon(iconName),
    h("div", { class: "toast-msg" }, message),
    h("button", { type: "button", class: "toast-close", "aria-label": "Dismiss notification", onclick: () => el.remove() }, icon("x")),
  );
  host.append(el);
  while (host.children.length > 4) host.firstElementChild.remove();
  if (timeout) setTimeout(() => el.remove(), timeout);
}

/* ---------- Tooltip (event delegation on [data-tip]) ---------- */
let tipEl = null;

function placeTip(x, y) {
  const pad = 12;
  const rect = tipEl.getBoundingClientRect();
  let left = x + 14;
  let top = y + 16;
  if (left + rect.width > window.innerWidth - pad) left = Math.max(pad, x - rect.width - 14);
  if (top + rect.height > window.innerHeight - pad) top = Math.max(pad, y - rect.height - 12);
  tipEl.style.left = `${left}px`;
  tipEl.style.top = `${top}px`;
}

export function initTooltips() {
  tipEl = h("div", { class: "tooltip", role: "tooltip", "aria-hidden": "true" });
  document.body.append(tipEl);
  const hide = () => tipEl.classList.remove("is-visible");
  const show = (target, x, y) => {
    const text = target.dataset.tip;
    if (!text) return hide();
    tipEl.textContent = text;
    tipEl.classList.add("is-visible");
    placeTip(x, y);
  };
  document.addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch") return;
    const target = e.target instanceof Element ? e.target.closest("[data-tip]") : null;
    if (target) show(target, e.clientX, e.clientY);
    else hide();
  });
  document.addEventListener("focusin", (e) => {
    const target = e.target instanceof Element ? e.target.closest("[data-tip]") : null;
    if (!target || !target.matches(":focus-visible")) return;
    const r = target.getBoundingClientRect();
    show(target, r.left + r.width / 2, r.bottom - 8);
  });
  document.addEventListener("focusout", hide);
  document.addEventListener("pointerdown", hide);
  window.addEventListener("scroll", hide, true);
  window.addEventListener("hashchange", hide);
}

/* ---------- Confirm dialog ---------- */
export function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    const cancel = h("button", { type: "button", class: "btn", value: "cancel" }, "Cancel");
    const ok = h("button", { type: "button", class: danger ? "btn btn-danger-solid" : "btn btn-primary" }, confirmLabel);
    const dialog = h(
      "dialog",
      { class: "dialog", "aria-labelledby": "dialog-title" },
      h("h2", { id: "dialog-title" }, title),
      h("p", null, message),
      h("div", { class: "dialog-actions" }, cancel, ok),
    );
    let result = false;
    cancel.addEventListener("click", () => dialog.close());
    ok.addEventListener("click", () => {
      result = true;
      dialog.close();
    });
    dialog.addEventListener("click", (e) => {
      if (e.target === dialog) dialog.close();
    });
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(result);
    });
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
}

/* ---------- Badges ---------- */
// Verdict and risk always pair colour with an icon and a word, so they stay
// readable without colour vision.
export function verdictBadge(verdict) {
  const mal = verdict === "malicious";
  return h("span", { class: `badge badge-${mal ? "malicious" : "benign"}` }, icon(mal ? "shield-alert" : "shield-check"), mal ? "Malicious" : "Benign");
}

const RISK_LEVELS = ["low", "medium", "high", "critical"];

export function riskBadge(level) {
  const known = RISK_LEVELS.includes(level) ? level : "medium";
  const bars = h(
    "span",
    { class: "risk-bars", "aria-hidden": "true" },
    RISK_LEVELS.map((_, i) => h("i", { class: i <= RISK_LEVELS.indexOf(known) ? "is-on" : null })),
  );
  return h("span", { class: `badge badge-${known} badge-risk` }, bars, `${titleCase(level || "unknown")} risk`);
}

export function probabilityMeter(probability, level) {
  const p = Math.max(0, Math.min(1, Number(probability) || 0));
  return h(
    "span",
    { class: `meter tone-${level || "medium"}`, "aria-label": `Malicious probability ${pct(p)}` },
    h("span", { class: "meter-track" }, h("span", { class: "meter-fill", style: { width: `${p * 100}%` } })),
    h("span", { class: "meter-value num" }, pct(p)),
  );
}

export function sourceLabel(source) {
  return source === "apk" ? "APK upload" : "Manual profile";
}

export function appCell(scan, { link = true } = {}) {
  const name = scan.app_name || "Unnamed app";
  const cls = ["app-name", "truncate", !scan.app_name && "is-unnamed"];
  return h(
    "div",
    { class: "app-cell" },
    h("span", { class: "app-icon" }, icon(scan.source === "apk" ? "package" : "sliders")),
    h(
      "div",
      { class: "truncate" },
      link ? h("a", { class: cls, href: `#/scans/${scan.id}`, title: name }, name) : h("span", { class: cls, title: name }, name),
      h("div", { class: "app-meta" }, sourceLabel(scan.source)),
    ),
  );
}

/* ---------- Loading / error states ---------- */
export function skeleton(cls, style) {
  return h("span", { class: `skeleton ${cls}`, style, "aria-hidden": "true" });
}

export function loadingBlock(...children) {
  return h("div", { class: "loading", role: "status", "aria-busy": "true" }, h("span", { class: "sr-only" }, "Loading"), children);
}

export function errorState(error, onRetry) {
  return h(
    "div",
    { class: "card" },
    h(
      "div",
      { class: "empty", role: "alert" },
      h("div", { class: "empty-icon" }, icon("alert")),
      h("h3", null, "Something went wrong"),
      h("p", null, (error && error.message) || "The request failed."),
      onRetry ? h("button", { type: "button", class: "btn", onclick: onRetry }, "Try again") : null,
    ),
  );
}

export function emptyState({ iconName = "info", title, text, action, small = false }) {
  return h(
    "div",
    { class: small ? "empty empty-sm" : "empty" },
    h("div", { class: "empty-icon" }, icon(iconName)),
    h("h3", null, title),
    text ? h("p", null, text) : null,
    action || null,
  );
}

export function pageHead({ eyebrow, title, sub, actions }) {
  return h(
    "header",
    { class: "page-head" },
    h(
      "div",
      { class: "page-head-text" },
      eyebrow ? h("div", { class: "eyebrow" }, eyebrow) : null,
      h("h1", { class: "page-title", tabindex: "-1" }, title),
      sub ? h("p", { class: "page-sub" }, sub) : null,
    ),
    actions ? h("div", { class: "page-actions" }, actions) : null,
  );
}

export function card({ title, sub, aside, body, cls = "", flush = false }) {
  return h(
    "section",
    { class: `card ${cls}` },
    title
      ? h(
          "div",
          { class: "card-head" },
          h("div", null, h("h2", { class: "card-title" }, title), sub ? h("p", { class: "card-sub" }, sub) : null),
          aside || null,
        )
      : null,
    h("div", { class: flush ? "card-flush" : "card-body" }, body),
  );
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Clipboard API needs a secure context; fall back to a hidden textarea.
    const ta = h("textarea", { class: "sr-only", value: text, readOnly: true });
    document.body.append(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    ta.remove();
    return ok;
  }
}
