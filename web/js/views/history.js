// History: searchable, filterable, paginated list of the user's scans.

import { api } from "../api.js";
import { h, mount, debounce } from "../dom.js";
import { icon } from "../icons.js";
import { dateTime, int, relativeTime } from "../format.js";
import { appCell, confirmDialog, emptyState, errorState, loadingBlock, pageHead, probabilityMeter, riskBadge, skeleton, toast, verdictBadge } from "../ui.js";

const PAGE_SIZE = 10;
const VERDICTS = [
  { id: "", label: "All" },
  { id: "malicious", label: "Malicious" },
  { id: "benign", label: "Benign" },
];

export function historyView({ query }) {
  const state = {
    q: query.get("q") || "",
    verdict: ["malicious", "benign"].includes(query.get("verdict")) ? query.get("verdict") : "",
    page: Math.max(1, parseInt(query.get("page"), 10) || 1),
  };
  let requestId = 0;

  const syncUrl = () => {
    const usp = new URLSearchParams();
    if (state.q) usp.set("q", state.q);
    if (state.verdict) usp.set("verdict", state.verdict);
    if (state.page > 1) usp.set("page", String(state.page));
    const str = usp.toString();
    // replaceState keeps filters shareable without re-running the router on every keystroke.
    history.replaceState(null, "", `#/history${str ? `?${str}` : ""}`);
  };

  const search = h("input", { class: "input", type: "search", placeholder: "Search by app name", "aria-label": "Search scans by app name", value: state.q, autocomplete: "off" });
  const filterBtns = VERDICTS.map((v) => {
    const btn = h("button", { type: "button", class: "seg-btn", "aria-pressed": String(state.verdict === v.id) }, v.label);
    btn.addEventListener("click", () => {
      if (state.verdict === v.id) return;
      state.verdict = v.id;
      state.page = 1;
      filterBtns.forEach((b, i) => b.setAttribute("aria-pressed", String(VERDICTS[i].id === state.verdict)));
      load();
    });
    return btn;
  });

  const results = h("div", { class: "history-results" });
  const summary = h("p", { class: "muted history-summary", "aria-live": "polite" });

  search.addEventListener(
    "input",
    debounce(() => {
      state.q = search.value.trim();
      state.page = 1;
      load();
    }, 280),
  );

  async function remove(scan) {
    const name = scan.app_name || "Unnamed app";
    const ok = await confirmDialog({
      title: "Delete this scan?",
      message: `“${name}” will be removed from your history. This cannot be undone.`,
      confirmLabel: "Delete scan",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.deleteScan(scan.id);
      toast("Scan deleted.", { type: "success" });
      load({ quiet: true });
    } catch (err) {
      if (err.status !== 401) toast(err.message || "Could not delete the scan.", { type: "error" });
    }
  }

  function table(items) {
    return h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        { class: "table table-history" },
        h(
          "thead",
          null,
          h("tr", null, h("th", null, "App"), h("th", null, "Verdict"), h("th", { class: "col-risk" }, "Risk level"), h("th", { class: "t-right" }, "Probability"), h("th", { class: "col-date" }, "Scanned"), h("th", null, h("span", { class: "sr-only" }, "Actions"))),
        ),
        h(
          "tbody",
          null,
          items.map((scan) => {
            const del = h("button", { type: "button", class: "btn btn-ghost btn-icon row-delete", "aria-label": `Delete scan of ${scan.app_name || "unnamed app"}`, dataset: { tip: "Delete scan" } }, icon("trash"));
            del.addEventListener("click", () => remove(scan));
            const row = h(
              "tr",
              { class: "is-clickable" },
              h("td", { class: "cell-app" }, appCell(scan)),
              h("td", { class: "cell-verdict" }, verdictBadge(scan.verdict)),
              h("td", { class: "col-risk" }, riskBadge(scan.risk_level)),
              h("td", { class: "t-right cell-prob" }, probabilityMeter(scan.probability, scan.risk_level)),
              h("td", { class: "col-date num muted", title: dateTime(scan.created_at) }, h("span", { class: "date-full" }, dateTime(scan.created_at)), h("span", { class: "date-rel" }, relativeTime(scan.created_at))),
              h("td", { class: "t-right cell-actions" }, del),
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

  function pager(total) {
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const from = (state.page - 1) * PAGE_SIZE + 1;
    const to = Math.min(total, state.page * PAGE_SIZE);
    const go = (page) => {
      state.page = page;
      load();
    };
    return h(
      "nav",
      { class: "pager", "aria-label": "Pagination" },
      h("span", { class: "muted num" }, `${int(from)}–${int(to)} of ${int(total)}`),
      h(
        "div",
        { class: "pager-buttons" },
        h("button", { type: "button", class: "btn btn-sm", disabled: state.page <= 1, onclick: () => go(state.page - 1) }, icon("chevron-left"), "Previous"),
        h("span", { class: "num muted pager-page" }, `Page ${state.page} of ${pages}`),
        h("button", { type: "button", class: "btn btn-sm", disabled: state.page >= pages, onclick: () => go(state.page + 1) }, "Next", icon("chevron-right")),
      ),
    );
  }

  async function load({ quiet = false } = {}) {
    const id = ++requestId;
    syncUrl();
    if (!quiet) {
      mount(results, loadingBlock(h("div", { class: "sk-rows" }, Array.from({ length: 6 }, () => skeleton("sk-line", { height: "44px", margin: "0 0 8px" })))));
    }
    try {
      const data = await api.scans({ limit: PAGE_SIZE, offset: (state.page - 1) * PAGE_SIZE, verdict: state.verdict, q: state.q });
      if (id !== requestId) return;
      const items = data.items || [];
      const total = data.total || 0;

      // Deleting the last row of the last page leaves an empty page; step back once.
      if (!items.length && total > 0 && state.page > 1) {
        state.page = Math.max(1, Math.ceil(total / PAGE_SIZE));
        load({ quiet });
        return;
      }

      const filtered = Boolean(state.q || state.verdict);
      summary.textContent = total ? `${int(total)} ${total === 1 ? "scan" : "scans"}${filtered ? " match your filters" : ""}` : "";

      if (!total) {
        mount(
          results,
          filtered
            ? emptyState({
                iconName: "search",
                title: "No scans match",
                text: "Try a different search term or clear the verdict filter.",
                action: h("button", {
                  type: "button",
                  class: "btn",
                  onclick: () => {
                    state.q = "";
                    state.verdict = "";
                    state.page = 1;
                    search.value = "";
                    filterBtns.forEach((b, i) => b.setAttribute("aria-pressed", String(i === 0)));
                    load();
                  },
                }, "Clear filters"),
              })
            : emptyState({
                iconName: "history",
                title: "No scans yet",
                text: "Every scan you run is saved here with its verdict and explanation.",
                action: h("a", { class: "btn btn-primary", href: "#/scan" }, icon("plus"), "New scan"),
              }),
        );
        return;
      }
      mount(results, table(items), pager(total));
    } catch (err) {
      if (id !== requestId || err.status === 401) return;
      summary.textContent = "";
      mount(results, errorState(err, () => load()));
    }
  }

  load();

  return h(
    "div",
    { class: "page page-history" },
    pageHead({
      eyebrow: "History",
      title: "Scan history",
      sub: "Every scan you have run, newest first.",
      actions: h("a", { class: "btn btn-primary", href: "#/scan" }, icon("plus"), "New scan"),
    }),
    h(
      "section",
      { class: "card" },
      h("div", { class: "history-toolbar" }, h("div", { class: "input-wrap history-search" }, icon("search"), search), h("div", { class: "seg", role: "group", "aria-label": "Filter by verdict" }, filterBtns), summary),
      results,
    ),
  );
}
