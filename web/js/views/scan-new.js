// New scan: upload an APK or build a manual feature profile.

import { api } from "../api.js";
import { h, mount, debounce } from "../dom.js";
import { icon } from "../icons.js";
import { bytes, plural, titleCase } from "../format.js";
import { errorState, loadingBlock, pageHead, skeleton, toast } from "../ui.js";

const CATEGORY_ORDER = ["permission", "api_call", "intent", "command", "file_artifact"];

function setMode(mode) {
  // replaceState keeps the tab in the URL without re-running the router.
  history.replaceState(null, "", mode === "manual" ? "#/scan?mode=manual" : "#/scan");
}

/* ---------- Upload APK ---------- */
function uploadPanel({ navigate, modelReady }) {
  const input = h("input", { type: "file", id: "apk-file", class: "sr-only", accept: ".apk,application/vnd.android.package-archive" });
  const status = h("div", { class: "upload-status", "aria-live": "polite" });
  const errorSlot = h("div", { "aria-live": "assertive" });
  let busy = false;

  const zone = h(
    "label",
    { class: "dropzone", for: "apk-file" },
    h("span", { class: "dropzone-icon" }, icon("upload")),
    h("strong", null, "Drop an APK here"),
    h("span", { class: "muted" }, "or ", h("span", { class: "dropzone-link" }, "browse your files")),
    h("span", { class: "hint" }, "Android packages (.apk). The file is analysed statically and never executed."),
  );

  const showError = (message, title) => {
    // Skip the heading when the server message already opens with the same words.
    if (title && message && message.toLowerCase().startsWith(title.toLowerCase())) title = null;
    mount(
      errorSlot,
      message ? h("div", { class: "alert", role: "alert" }, icon("alert"), h("div", null, title ? h("strong", { class: "alert-title" }, title) : null, h("span", null, message))) : null,
    );
  };

  const reset = () => {
    busy = false;
    zone.classList.remove("is-busy");
    input.disabled = false;
    input.value = "";
    mount(status);
  };

  const start = async (file) => {
    if (busy || !file) return;
    showError(null);
    if (!/\.apk$/i.test(file.name)) {
      showError(`“${file.name}” does not look like an APK. Choose a file ending in .apk.`);
      input.value = "";
      return;
    }
    if (file.size === 0) {
      showError("That file is empty.");
      input.value = "";
      return;
    }
    busy = true;
    zone.classList.add("is-busy");
    input.disabled = true;

    const bar = h("div", { class: "progress-bar", style: { width: "0%" } });
    const progress = h("div", { class: "progress", role: "progressbar", "aria-label": "Upload progress", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": "0" }, bar);
    const phase = h("span", { class: "muted" }, "Uploading… 0%");
    mount(
      status,
      h(
        "div",
        { class: "upload-file" },
        h("span", { class: "app-icon" }, icon("package")),
        h("div", { class: "truncate upload-file-text" }, h("strong", { class: "truncate" }, file.name), h("span", { class: "faint num" }, bytes(file.size))),
        phase,
      ),
      progress,
    );

    try {
      const scan = await api.scanApk(file, (fraction) => {
        const p = Math.round(fraction * 100);
        bar.style.width = `${p}%`;
        progress.setAttribute("aria-valuenow", String(p));
        if (p >= 100) {
          progress.classList.add("is-indeterminate");
          progress.removeAttribute("aria-valuenow");
          phase.textContent = "Analysing…";
        } else {
          phase.textContent = `Uploading… ${p}%`;
        }
      });
      toast("Scan complete.", { type: "success" });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      reset();
      if (err.status === 401) return;
      const title = err.status === 413 ? "File too large" : err.status === 400 ? "Not a valid APK" : "Upload failed";
      showError(err.message || "The upload failed.", title);
    }
  };

  input.addEventListener("change", () => start(input.files && input.files[0]));
  ["dragenter", "dragover"].forEach((type) =>
    zone.addEventListener(type, (e) => {
      e.preventDefault();
      if (!busy) zone.classList.add("is-over");
    }),
  );
  ["dragleave", "dragend"].forEach((type) => zone.addEventListener(type, () => zone.classList.remove("is-over")));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("is-over");
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    start(file);
  });

  const facts = [
    ["file", "Manifest", "Requested permissions and declared intent filters."],
    ["layers", "Bytecode", "API calls and suspicious strings found in the DEX files."],
    ["shield", "Private", "Results are stored in your account only."],
  ];

  return h(
    "div",
    { class: "upload-panel", role: "tabpanel", "aria-label": "Upload APK" },
    h(
      "section",
      { class: "card" },
      h("div", { class: "card-body upload-body" }, input, zone, errorSlot, status, modelReady ? null : h("p", { class: "hint" }, "No trained model is loaded, so the scan will fail until one is available.")),
    ),
    h(
      "ul",
      { class: "fact-row" },
      facts.map(([ic, title, text]) => h("li", null, h("span", { class: "fact-icon" }, icon(ic)), h("div", null, h("strong", null, title), h("span", null, text)))),
    ),
  );
}

/* ---------- Manual profile ---------- */
function manualPanel({ navigate, catalog, presets }) {
  const features = catalog.features || [];
  const categories = catalog.categories || {};
  const order = [...CATEGORY_ORDER.filter((c) => features.some((f) => f.category === c)), ...new Set(features.map((f) => f.category).filter((c) => !CATEGORY_ORDER.includes(c)))];
  const selected = new Set();
  const checkboxes = new Map();
  const rows = new Map();
  const groups = new Map();
  let activePreset = null;

  const nameInput = h("input", { class: "input", id: "app-name", type: "text", maxLength: 120, placeholder: "e.g. flashlight-pro.apk", autocomplete: "off" });
  const count = h("strong", { class: "num" }, "0");
  const countLabel = h("span", null, " indicators selected");
  const liveCount = h("span", { class: "sr-only", "aria-live": "polite" });
  const announce = debounce(() => {
    liveCount.textContent = `${plural(selected.size, "indicator")} selected`;
  }, 400);
  const noMatch = h("p", { class: "muted note-empty", hidden: true }, "No indicators match your search.");
  const submit = h("button", { type: "submit", class: "btn btn-primary btn-lg" }, icon("scan"), "Run scan");
  const clearAll = h("button", { type: "button", class: "btn btn-ghost" }, "Clear all");
  const presetButtons = new Map();

  const sync = () => {
    count.textContent = String(selected.size);
    countLabel.textContent = selected.size === 1 ? " indicator selected" : " indicators selected";
    clearAll.disabled = selected.size === 0;
    for (const [category, group] of groups) {
      const inCat = features.filter((f) => f.category === category);
      const on = inCat.filter((f) => selected.has(f.slug)).length;
      group.counter.textContent = `${on}/${inCat.length}`;
      const all = on === inCat.length;
      group.toggle.textContent = all ? "Clear" : "Select all";
      group.toggle.setAttribute("aria-label", `${all ? "Clear" : "Select all"} ${group.name}`);
    }
    for (const [id, btn] of presetButtons) {
      btn.classList.toggle("is-active", id === activePreset);
      btn.setAttribute("aria-pressed", String(id === activePreset));
    }
    announce();
  };

  const setFeature = (slug, on) => {
    if (on) selected.add(slug);
    else selected.delete(slug);
    const box = checkboxes.get(slug);
    if (box) box.checked = on;
    const row = rows.get(slug);
    if (row) row.classList.toggle("is-on", on);
  };

  const featureRow = (f) => {
    const id = `feat-${f.slug}`;
    const box = h("input", { type: "checkbox", id, role: "switch", "aria-describedby": `${id}-desc` });
    box.addEventListener("change", () => {
      activePreset = null;
      setFeature(f.slug, box.checked);
      sync();
    });
    checkboxes.set(f.slug, box);
    const row = h(
      "label",
      { class: "feature-row", for: id },
      h("span", { class: "switch" }, box, h("span", { class: "switch-track" })),
      h("span", { class: "feature-text" }, h("span", { class: "feature-label" }, f.label), h("span", { class: "feature-desc", id: `${id}-desc` }, f.description)),
    );
    rows.set(f.slug, row);
    return row;
  };

  const groupEls = order.map((category) => {
    const inCat = features.filter((f) => f.category === category);
    const name = categories[category] || titleCase(category.replace(/_/g, " "));
    const counter = h("span", { class: "badge badge-plain num" }, `0/${inCat.length}`);
    const toggle = h("button", { type: "button", class: "btn btn-sm btn-ghost" }, "Select all");
    toggle.addEventListener("click", () => {
      const all = inCat.every((f) => selected.has(f.slug));
      activePreset = null;
      inCat.forEach((f) => setFeature(f.slug, !all));
      sync();
    });
    const el = h(
      "fieldset",
      { class: "card feature-group" },
      h("legend", { class: "sr-only" }, name),
      h("div", { class: "feature-group-head" }, h("h3", { "aria-hidden": "true" }, name), counter, toggle),
      h("div", { class: "feature-list" }, inCat.map(featureRow)),
    );
    groups.set(category, { el, counter, toggle, name });
    return el;
  });

  const search = h("input", { class: "input", type: "search", id: "feature-search", placeholder: "Filter indicators", "aria-label": "Filter indicators", autocomplete: "off" });
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    let visible = 0;
    for (const f of features) {
      const hit = !q || `${f.label} ${f.description} ${f.slug}`.toLowerCase().includes(q);
      rows.get(f.slug).hidden = !hit;
      if (hit) visible += 1;
    }
    for (const [category, group] of groups) {
      group.el.hidden = !features.some((f) => f.category === category && !rows.get(f.slug).hidden);
    }
    noMatch.hidden = visible > 0;
  });

  clearAll.addEventListener("click", () => {
    activePreset = null;
    features.forEach((f) => setFeature(f.slug, false));
    sync();
  });

  const presetCards = (presets || []).map((preset) => {
    const mal = preset.expected === "malicious";
    const on = Object.values(preset.features || {}).filter(Boolean).length;
    const btn = h(
      "button",
      { type: "button", class: "preset", "aria-pressed": "false", dataset: { tip: preset.description || "" } },
      h("span", { class: "preset-top" }, h("strong", null, preset.name), h("span", { class: `badge badge-${mal ? "malicious" : "benign"}` }, icon(mal ? "shield-alert" : "shield-check"), mal ? "Malicious" : "Benign")),
      h("span", { class: "preset-desc" }, preset.description),
      h("span", { class: "preset-meta eyebrow" }, `${on} indicators`),
    );
    btn.addEventListener("click", () => {
      features.forEach((f) => setFeature(f.slug, Boolean(preset.features && preset.features[f.slug])));
      activePreset = preset.id;
      if (!nameInput.value.trim() || nameInput.dataset.fromPreset) {
        nameInput.value = `${preset.name} (example)`;
        nameInput.dataset.fromPreset = "1";
      }
      sync();
    });
    presetButtons.set(preset.id, btn);
    return btn;
  });
  nameInput.addEventListener("input", () => delete nameInput.dataset.fromPreset);

  const form = h(
    "form",
    { class: "manual", role: "tabpanel", "aria-label": "Manual profile", novalidate: true },
    h(
      "section",
      { class: "card" },
      h(
        "div",
        { class: "card-body manual-top" },
        h("div", { class: "field manual-name" }, h("label", { class: "label", for: "app-name" }, "App name", h("span", { class: "optional" }, "optional")), nameInput, h("span", { class: "hint" }, "Shown in your history so you can find this scan later.")),
        presetCards.length
          ? h("div", { class: "manual-presets" }, h("div", { class: "label" }, "Start from an example"), h("div", { class: "preset-grid" }, presetCards))
          : null,
      ),
    ),
    h(
      "div",
      { class: "manual-toolbar" },
      h("div", { class: "input-wrap manual-search" }, icon("search"), search),
      h("p", { class: "muted" }, plural(features.length, "indicator"), " in ", plural(order.length, "category", "categories"), ". Switch on everything the app does."),
    ),
    h("div", { class: "feature-groups" }, groupEls),
    noMatch,
    h("div", { class: "action-bar" }, h("div", { class: "action-bar-inner" }, h("p", { class: "action-count" }, count, countLabel, liveCount), h("div", { class: "action-buttons" }, clearAll, submit))),
  );

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.classList.add("is-loading");
    submit.disabled = true;
    const body = { features: Object.fromEntries(features.map((f) => [f.slug, selected.has(f.slug) ? 1 : 0])) };
    const appName = nameInput.value.trim();
    if (appName) body.app_name = appName;
    try {
      const scan = await api.scanManual(body);
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      submit.classList.remove("is-loading");
      submit.disabled = false;
      if (err.status !== 401) toast(err.message || "The scan failed.", { type: "error" });
    }
  });

  sync();
  return form;
}

export function newScanView({ query, navigate, health }) {
  let mode = query.get("mode") === "manual" ? "manual" : "apk";
  const modelReady = !health || health.model_loaded !== false;
  const body = h("div", { class: "scan-body" });
  let manualData = null;

  const tabs = [
    { id: "apk", label: "Upload APK", icon: "upload" },
    { id: "manual", label: "Manual profile", icon: "sliders" },
  ].map((t) => {
    const btn = h("button", { type: "button", class: "seg-btn", role: "tab", id: `tab-${t.id}` }, icon(t.icon), t.label);
    btn.addEventListener("click", () => {
      if (mode === t.id) return;
      mode = t.id;
      setMode(mode);
      paint();
    });
    return { ...t, btn };
  });

  const tablist = h("div", { class: "seg seg-lg", role: "tablist", "aria-label": "Scan mode" }, tabs.map((t) => t.btn));
  tablist.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const next = tabs.find((t) => t.id !== mode);
    next.btn.click();
    next.btn.focus();
  });

  const loadManual = async () => {
    mount(body, loadingBlock(skeleton("sk-block"), h("div", { class: "feature-groups" }, skeleton("sk-tall"), skeleton("sk-tall"))));
    try {
      if (!manualData) {
        const [catalog, presets] = await Promise.all([api.features(), api.presets().catch(() => ({ presets: [] }))]);
        manualData = { catalog, presets: presets.presets || [] };
      }
      if (mode === "manual") mount(body, manualPanel({ navigate, ...manualData }));
    } catch (err) {
      if (err.status !== 401 && mode === "manual") mount(body, errorState(err, loadManual));
    }
  };

  function paint() {
    for (const t of tabs) {
      const active = t.id === mode;
      t.btn.setAttribute("aria-selected", String(active));
      t.btn.tabIndex = active ? 0 : -1;
    }
    if (mode === "apk") mount(body, uploadPanel({ navigate, modelReady }));
    else loadManual();
  }

  paint();
  return h(
    "div",
    { class: "page page-scan" },
    pageHead({
      eyebrow: "New scan",
      title: "Scan an app",
      sub: "Upload an APK for automatic feature extraction, or describe the app yourself.",
    }),
    tablist,
    body,
  );
}
