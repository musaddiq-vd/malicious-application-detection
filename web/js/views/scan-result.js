// Scan result: verdict, risk gauge and the explanation behind the score.

import { api } from "../api.js";
import { h, mount } from "../dom.js";
import { icon } from "../icons.js";
import { gauge } from "../charts.js";
import { bytes, dateTime, pct, signedPts, titleCase, plural } from "../format.js";
import { card, confirmDialog, copyText, emptyState, errorState, loadingBlock, riskBadge, skeleton, sourceLabel, toast } from "../ui.js";

const CATEGORY_ORDER = ["permission", "api_call", "intent", "command", "file_artifact"];
const TOP_N = 10;

function categoryName(id, categories) {
  return (categories && categories[id]) || titleCase(String(id || "other").replace(/_/g, " "));
}

function verdictSentence(scan) {
  const p = pct(scan.probability, 1);
  const t = pct(scan.threshold);
  return scan.verdict === "malicious"
    ? `The model estimates a ${p} probability that this app is malicious, which is at or above the ${t} decision threshold.`
    : `The model estimates a ${p} probability that this app is malicious, which is below the ${t} decision threshold.`;
}

function hero(scan) {
  const mal = scan.verdict === "malicious";
  return h(
    "section",
    { class: `card verdict verdict-${mal ? "malicious" : "benign"}`, "aria-live": "polite" },
    h(
      "div",
      { class: "verdict-text" },
      h("div", { class: "verdict-mark" }, icon(mal ? "shield-alert" : "shield-check")),
      h("div", { class: "eyebrow" }, "Verdict"),
      h("h2", { class: "verdict-title" }, mal ? "Malicious" : "Benign"),
      h("p", { class: "verdict-sentence" }, verdictSentence(scan)),
      h("div", { class: "verdict-tags" }, riskBadge(scan.risk_level), h("span", { class: "badge badge-plain" }, sourceLabel(scan.source)), scan.model_name ? h("span", { class: "badge badge-plain" }, scan.model_name) : null),
    ),
    h("div", { class: "verdict-gauge" }, gauge({ probability: scan.probability, threshold: scan.threshold, riskLevel: scan.risk_level })),
  );
}

function contributionRow(c, max) {
  const up = c.impact > 0;
  const zero = c.impact === 0;
  const width = max > 0 ? Math.max(zero ? 0 : 1.5, (Math.abs(c.impact) / max) * 50) : 0;
  return h(
    "li",
    {
      class: `contrib ${zero ? "is-zero" : up ? "is-up" : "is-down"}`,
      dataset: { tip: `${c.label} is ${c.value ? "present" : "absent"}.\nThat ${zero ? "does not change" : up ? "raises" : "lowers"} the malicious probability${zero ? "." : ` by ${Math.abs(c.impact * 100).toFixed(1)} points.`}` },
    },
    h("div", { class: "contrib-label" }, h("span", { class: "truncate" }, c.label), h("span", { class: `state-tag ${c.value ? "is-on" : ""}` }, c.value ? "present" : "absent")),
    h("div", { class: "contrib-track", "aria-hidden": "true" }, h("span", { class: "contrib-bar", style: { width: `${width}%` } })),
    h("div", { class: "contrib-value num" }, zero ? "0.00" : signedPts(c.impact, Math.abs(c.impact) < 0.01 ? 2 : 1), h("span", { class: "sr-only" }, ` percentage points ${up ? "toward malicious" : "toward benign"}`)),
  );
}

function contributionsCard(scan) {
  const all = Array.isArray(scan.contributions) ? scan.contributions : [];
  if (!all.length) {
    return card({ title: "Why this verdict", body: h("p", { class: "muted" }, "No feature contributions were returned for this scan.") });
  }
  const max = Math.max(...all.map((c) => Math.abs(c.impact)), 0);
  const list = h("ol", { class: "contribs" });
  let expanded = false;
  const toggle = h("button", { type: "button", class: "btn btn-sm" });
  const paint = () => {
    mount(list, (expanded ? all : all.slice(0, TOP_N)).map((c) => contributionRow(c, max)));
    toggle.textContent = expanded ? `Show top ${TOP_N}` : `Show all ${all.length}`;
    toggle.setAttribute("aria-expanded", String(expanded));
  };
  toggle.addEventListener("click", () => {
    expanded = !expanded;
    paint();
  });
  paint();

  return card({
    title: "Why this verdict",
    sub: "The features that moved the score the most",
    cls: "contrib-card",
    body: [
      h(
        "p",
        { class: "explain" },
        icon("info"),
        h(
          "span",
          null,
          "Each bar is the change in malicious probability caused by one feature being present or absent, in percentage points. ",
          h("b", { class: "txt-mal" }, "Bars to the right push toward malicious"),
          "; ",
          h("b", { class: "txt-ben" }, "bars to the left push toward benign"),
          ".",
        ),
      ),
      h("div", { class: "contrib-axis", "aria-hidden": "true" }, h("span", null), h("span", { class: "contrib-axis-labels" }, h("span", null, icon("arrow-left"), "Toward benign"), h("span", null, "Toward malicious", icon("arrow-right"))), h("span", { class: "contrib-axis-unit" }, "pts")),
      list,
      all.length > TOP_N ? h("div", { class: "contrib-more" }, toggle) : null,
    ],
  });
}

function profileCard(scan, catalog) {
  const meta = new Map();
  for (const f of (catalog && catalog.features) || []) meta.set(f.slug, f);
  for (const c of scan.contributions || []) if (!meta.has(c.slug)) meta.set(c.slug, c);
  const slugs = Object.keys(scan.features || {});
  const onCount = slugs.filter((sl) => scan.features[sl]).length;

  const byCat = new Map();
  for (const slug of slugs) {
    const info = meta.get(slug) || { slug, label: slug, category: "other" };
    if (!byCat.has(info.category)) byCat.set(info.category, []);
    byCat.get(info.category).push({ ...info, slug, on: Boolean(scan.features[slug]) });
  }
  const order = [...CATEGORY_ORDER.filter((c) => byCat.has(c)), ...[...byCat.keys()].filter((c) => !CATEGORY_ORDER.includes(c))];

  const wrap = h("div", { class: "profile" });
  let onlyOn = false;
  const filterBtn = h("button", { type: "button", class: "btn btn-sm", "aria-pressed": "false" }, "Show present only");
  const paint = () => {
    mount(
      wrap,
      order.map((cat) => {
        const items = byCat.get(cat).filter((f) => !onlyOn || f.on);
        const present = byCat.get(cat).filter((f) => f.on).length;
        return h(
          "div",
          { class: "profile-group" },
          h("h3", { class: "profile-cat" }, categoryName(cat, catalog && catalog.categories), h("span", { class: "faint num" }, `${present}/${byCat.get(cat).length}`)),
          items.length
            ? h(
                "ul",
                { class: "chip-list" },
                items.map((f) =>
                  h("li", { class: `chip ${f.on ? "is-on" : ""}`, dataset: f.description ? { tip: f.description } : null }, icon(f.on ? "check" : "minus"), h("span", null, f.label), h("span", { class: "sr-only" }, f.on ? " (present)" : " (absent)")),
                ),
              )
            : h("p", { class: "faint profile-none" }, "None present"),
        );
      }),
    );
  };
  filterBtn.addEventListener("click", () => {
    onlyOn = !onlyOn;
    filterBtn.setAttribute("aria-pressed", String(onlyOn));
    filterBtn.textContent = onlyOn ? "Show all features" : "Show present only";
    paint();
  });
  paint();

  return card({
    title: "Feature profile",
    sub: `${onCount} of ${plural(slugs.length, "indicator")} present`,
    aside: filterBtn,
    body: wrap,
  });
}

function apkCards(scan, catalog) {
  const apk = scan.apk;
  if (!apk) return [];
  const labels = new Map(((catalog && catalog.features) || []).map((f) => [f.slug, f.label]));
  for (const c of scan.contributions || []) if (!labels.has(c.slug)) labels.set(c.slug, c.label);

  const copyBtn = h("button", { type: "button", class: "btn btn-sm btn-icon", "aria-label": "Copy SHA-256", dataset: { tip: "Copy SHA-256" } }, icon("copy"));
  copyBtn.addEventListener("click", async () => {
    const ok = await copyText(apk.sha256 || "");
    toast(ok ? "SHA-256 copied to clipboard." : "Could not copy to the clipboard.", { type: ok ? "success" : "error" });
    if (ok) {
      mount(copyBtn, icon("check"));
      setTimeout(() => mount(copyBtn, icon("copy")), 1600);
    }
  });

  const permissions = Array.isArray(apk.permissions) ? apk.permissions : [];
  const evidence = Object.entries(apk.evidence || {});

  const details = card({
    title: "Package",
    sub: "Extracted from the uploaded APK",
    body: h(
      "dl",
      { class: "facts" },
      h("div", { class: "facts-wide" }, h("dt", null, "Package name"), h("dd", { class: "mono wrap" }, apk.package || "Unknown")),
      h("div", null, h("dt", null, "File size"), h("dd", { class: "num" }, bytes(apk.size_bytes))),
      h("div", null, h("dt", null, "DEX files"), h("dd", { class: "num" }, apk.dex_count ?? "–")),
      h("div", { class: "facts-wide" }, h("dt", null, "SHA-256"), h("dd", { class: "hash" }, h("code", { class: "wrap" }, apk.sha256 || "–"), apk.sha256 ? copyBtn : null)),
    ),
  });

  const perms = card({
    title: "Declared permissions",
    sub: plural(permissions.length, "permission"),
    body: permissions.length
      ? h(
          "ul",
          { class: "perm-list" },
          permissions.map((perm) => {
            const str = String(perm);
            const cut = str.lastIndexOf(".");
            return h("li", { class: "mono" }, cut > 0 ? h("span", { class: "faint" }, str.slice(0, cut + 1)) : null, cut > 0 ? str.slice(cut + 1) : str);
          }),
        )
      : h("p", { class: "muted" }, "The manifest does not request any permissions."),
  });

  const ev = card({
    title: "Evidence",
    sub: "What the analyser matched for each detected feature",
    body: evidence.length
      ? h(
          "dl",
          { class: "evidence" },
          evidence.map(([slug, text]) => h("div", null, h("dt", null, labels.get(slug) || slug), h("dd", { class: "mono wrap" }, String(text)))),
        )
      : h("p", { class: "muted" }, "No features were detected in this package."),
  });

  return [h("div", { class: "grid grid-1-1" }, details, perms), ev];
}

function resultPage(scan, catalog, { navigate }) {
  const name = scan.app_name || "Unnamed app";
  const del = h("button", { type: "button", class: "btn btn-danger" }, icon("trash"), "Delete");
  del.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "Delete this scan?",
      message: `“${name}” will be removed from your history. This cannot be undone.`,
      confirmLabel: "Delete scan",
      danger: true,
    });
    if (!ok) return;
    del.classList.add("is-loading");
    try {
      await api.deleteScan(scan.id);
      toast("Scan deleted.", { type: "success" });
      navigate("/history");
    } catch (err) {
      del.classList.remove("is-loading");
      if (err.status !== 401) toast(err.message || "Could not delete the scan.", { type: "error" });
    }
  });

  return h(
    "div",
    { class: "page page-result" },
    h("a", { class: "back-link", href: "#/history" }, icon("arrow-left"), "History"),
    h(
      "header",
      { class: "page-head" },
      h(
        "div",
        { class: "page-head-text" },
        h("div", { class: "eyebrow num" }, `Scan #${scan.id}`),
        h("h1", { class: ["page-title", "wrap", !scan.app_name && "is-unnamed"], tabindex: "-1" }, name),
        h("p", { class: "page-sub" }, `${sourceLabel(scan.source)} · ${dateTime(scan.created_at)}`),
      ),
      h("div", { class: "page-actions" }, h("a", { class: "btn", href: scan.source === "manual" ? "#/scan?mode=manual" : "#/scan" }, icon("scan"), "Scan another"), del),
    ),
    hero(scan),
    contributionsCard(scan),
    profileCard(scan, catalog),
    apkCards(scan, catalog),
  );
}

export function scanResultView(ctx) {
  const id = ctx.params[0];
  const root = h("div", { class: "view" });

  const load = async () => {
    mount(root, h("div", { class: "page page-result" }, loadingBlock(skeleton("sk-title"), skeleton("sk-tall", { marginTop: "24px" }), skeleton("sk-tall", { marginTop: "24px" }))));
    try {
      // The catalog only adds descriptions and category names; the result still renders without it.
      const [scan, catalog] = await Promise.all([api.scan(id), api.features().catch(() => null)]);
      mount(root, resultPage(scan, catalog, ctx));
    } catch (err) {
      if (err.status === 401) return;
      if (err.status === 404) {
        mount(
          root,
          h(
            "div",
            { class: "page" },
            h(
              "div",
              { class: "card" },
              emptyState({
                iconName: "search",
                title: "Scan not found",
                text: "It may have been deleted, or it belongs to another account.",
                action: h("a", { class: "btn btn-primary", href: "#/history" }, "Go to history"),
              }),
            ),
          ),
        );
        return;
      }
      mount(root, h("div", { class: "page" }, errorState(err, load)));
    }
  };
  load();
  return root;
}
