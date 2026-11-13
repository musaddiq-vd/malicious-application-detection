// Application entry: session bootstrap, hash router and the signed-in shell.

import { api, onUnauthorized } from "./api.js";
import { h, mount } from "./dom.js";
import { icon, logoMark } from "./icons.js";
import { initials } from "./format.js";
import { initTooltips, themeToggle, toast } from "./ui.js";
import { authView } from "./views/auth.js";
import { dashboardView } from "./views/dashboard.js";
import { newScanView } from "./views/scan-new.js";
import { scanResultView } from "./views/scan-result.js";
import { historyView } from "./views/history.js";
import { insightsView } from "./views/insights.js";

const state = {
  user: null,
  health: null,
  shell: null,
  returnTo: null,
};

const ROUTES = [
  { pattern: /^\/$/, view: dashboardView, nav: "dashboard", title: "Dashboard" },
  { pattern: /^\/scan$/, view: newScanView, nav: "scan", title: "New scan" },
  { pattern: /^\/scans\/(\d+)$/, view: scanResultView, nav: "history", title: "Scan result" },
  { pattern: /^\/history$/, view: historyView, nav: "history", title: "History" },
  { pattern: /^\/insights$/, view: insightsView, nav: "insights", title: "Model insights" },
];

const NAV = [
  { id: "dashboard", href: "#/", label: "Dashboard", icon: "dashboard" },
  { id: "scan", href: "#/scan", label: "New scan", icon: "scan" },
  { id: "history", href: "#/history", label: "History", icon: "history" },
  { id: "insights", href: "#/insights", label: "Model insights", short: "Insights", icon: "insights" },
];

/* ---------- Routing ---------- */
function parseHash() {
  const raw = window.location.hash.replace(/^#/, "") || "/";
  const [path, search = ""] = raw.split("?");
  return { path: path.startsWith("/") ? path : `/${path}`, query: new URLSearchParams(search) };
}

export function navigate(to, { replace = false } = {}) {
  const target = `#${to}`;
  if (window.location.hash === target) {
    render();
  } else if (replace) {
    window.location.replace(target);
  } else {
    window.location.hash = target;
  }
}

function setTitle(title) {
  document.title = title ? `${title} · MalDetect` : "MalDetect";
}

function render() {
  const { path, query } = parseHash();
  const root = document.getElementById("app");
  const isAuthRoute = path === "/login" || path === "/register";

  if (!state.user) {
    if (!isAuthRoute) {
      state.returnTo = path === "/" ? null : window.location.hash.slice(1);
      navigate("/login", { replace: true });
      return;
    }
    state.shell = null;
    setTitle(path === "/register" ? "Create account" : "Sign in");
    mount(root, authView({ mode: path === "/register" ? "register" : "login", onAuthenticated }));
    return;
  }

  if (isAuthRoute) {
    navigate("/", { replace: true });
    return;
  }

  const route = ROUTES.find((r) => r.pattern.test(path));
  if (!state.shell) {
    state.shell = buildShell();
    mount(root, state.shell.el);
  }
  state.shell.setActive(route ? route.nav : null);
  state.shell.closeMenus();

  const ctx = { params: route ? path.match(route.pattern).slice(1) : [], query, navigate, user: state.user, health: state.health };
  setTitle(route ? route.title : "Not found");
  const page = route ? route.view(ctx) : notFoundView();
  mount(state.shell.outlet, page);
  window.scrollTo(0, 0);
  // Move focus to the new page heading so keyboard and screen-reader users land in the right place.
  const heading = page.querySelector(".page-title");
  if (heading && state.shell.hasNavigated) heading.focus({ preventScroll: true });
  state.shell.hasNavigated = true;
}

function notFoundView() {
  return h(
    "div",
    { class: "page" },
    h(
      "div",
      { class: "card" },
      h(
        "div",
        { class: "empty" },
        h("div", { class: "empty-icon" }, icon("search")),
        h("h3", { class: "page-title", tabindex: "-1" }, "Page not found"),
        h("p", null, "That address does not match any screen in MalDetect."),
        h("a", { class: "btn btn-primary", href: "#/" }, "Back to dashboard"),
      ),
    ),
  );
}

/* ---------- Session ---------- */
function onAuthenticated(user) {
  state.user = user;
  api.clearCache();
  const target = state.returnTo || "/";
  state.returnTo = null;
  refreshHealth();
  navigate(target, { replace: true });
}

async function signOut() {
  try {
    await api.logout();
  } catch {
    /* the local session is dropped either way */
  }
  state.user = null;
  api.clearCache();
  navigate("/login");
  toast("You have been signed out.");
}

onUnauthorized(() => {
  if (!state.user) return;
  state.user = null;
  const { path } = parseHash();
  state.returnTo = path === "/" ? null : window.location.hash.slice(1);
  api.clearCache();
  toast("Your session has expired. Please sign in again.", { type: "error" });
  navigate("/login");
});

async function refreshHealth() {
  try {
    state.health = await api.health();
  } catch {
    state.health = null;
  }
  if (state.shell) state.shell.setHealth(state.health);
}

/* ---------- Shell ---------- */
function userMenu(direction) {
  const user = state.user;
  const wrap = h("div", { class: "menu-wrap" });
  let menu = null;

  const close = () => {
    if (!menu) return;
    menu.remove();
    menu = null;
    trigger.setAttribute("aria-expanded", "false");
  };
  const open = () => {
    menu = h(
      "div",
      { class: `menu menu-${direction}`, role: "menu" },
      h("div", { class: "menu-head" }, h("strong", { class: "truncate" }, user.full_name || user.username), h("span", { class: "truncate" }, user.email || `@${user.username}`)),
      h("button", { type: "button", class: "menu-item", role: "menuitem", onclick: signOut }, icon("logout"), "Sign out"),
    );
    wrap.append(menu);
    trigger.setAttribute("aria-expanded", "true");
    menu.querySelector(".menu-item").focus();
  };

  const trigger = h(
    "button",
    {
      type: "button",
      class: direction === "up" ? "user-btn" : "user-btn user-btn-compact",
      "aria-haspopup": "menu",
      "aria-expanded": "false",
      "aria-label": `Account menu for ${user.full_name || user.username}`,
      onclick: () => (menu ? close() : open()),
    },
    h("span", { class: "avatar" }, initials(user.full_name || user.username)),
    direction === "up"
      ? [
          h("span", { class: "user-text truncate" }, h("strong", { class: "truncate" }, user.full_name || user.username), h("span", { class: "truncate" }, `@${user.username}`)),
          icon("chevron-down"),
        ]
      : null,
  );
  wrap.append(trigger);

  document.addEventListener("click", (e) => {
    if (menu && !wrap.contains(e.target)) close();
  });
  wrap.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && menu) {
      close();
      trigger.focus();
    }
  });
  return { el: wrap, close };
}

function buildShell() {
  const brand = () => h("a", { class: "brand", href: "#/", "aria-label": "MalDetect dashboard" }, logoMark(26), h("span", { class: "brand-name" }, "Mal", h("b", null, "Detect")));

  const navLinks = NAV.map((item) => h("a", { class: "nav-link", href: item.href, dataset: { nav: item.id } }, icon(item.icon), h("span", null, item.label)));
  const tabLinks = NAV.map((item) => h("a", { class: "tab-link", href: item.href, dataset: { nav: item.id } }, icon(item.icon), h("span", null, item.short || item.label)));

  const modelStatus = h("div", { class: "model-status" });
  const banner = h("div", { class: "banner-slot" });
  const menus = [userMenu("up"), userMenu("down")];

  const sidebar = h(
    "aside",
    { class: "sidebar" },
    brand(),
    h("nav", { class: "nav", "aria-label": "Primary" }, h("div", { class: "eyebrow nav-eyebrow" }, "Workspace"), navLinks),
    h("div", { class: "sidebar-foot" }, modelStatus, h("div", { class: "sidebar-row" }, themeToggle({ withLabel: true })), menus[0].el),
  );

  const topbar = h("header", { class: "topbar" }, brand(), h("div", { class: "topbar-actions" }, themeToggle(), menus[1].el));
  const tabbar = h("nav", { class: "tabbar", "aria-label": "Primary" }, tabLinks);
  const outlet = h("div", { class: "outlet" });
  const main = h("main", { class: "main", id: "main", tabindex: "-1" }, banner, outlet);
  const el = h("div", { class: "shell" }, sidebar, topbar, main, tabbar);

  const shell = {
    el,
    outlet,
    hasNavigated: false,
    setActive(id) {
      for (const link of [...navLinks, ...tabLinks]) {
        const active = link.dataset.nav === id;
        link.classList.toggle("is-active", active);
        if (active) link.setAttribute("aria-current", "page");
        else link.removeAttribute("aria-current");
      }
    },
    closeMenus() {
      menus.forEach((m) => m.close());
    },
    setHealth(health) {
      const loaded = Boolean(health && health.model_loaded);
      const reachable = Boolean(health);
      mount(
        modelStatus,
        h("span", { class: `status-dot ${loaded ? "is-ok" : reachable ? "is-warn" : "is-off"}`, "aria-hidden": "true" }),
        h(
          "div",
          { class: "truncate" },
          h("strong", null, loaded ? "Model ready" : reachable ? "Model not trained" : "Status unknown"),
          h("span", { class: "num" }, health && health.version ? `v${health.version}` : "–"),
        ),
      );
      mount(
        banner,
        reachable && !loaded
          ? h(
              "div",
              { class: "alert alert-warn banner", role: "status" },
              icon("alert"),
              h(
                "div",
                null,
                h("strong", null, "No trained model is loaded. "),
                "Scans are unavailable until the model has been trained on the server. Your history and the rest of the app still work.",
              ),
            )
          : null,
      );
    },
  };
  shell.setHealth(state.health);
  return shell;
}

/* ---------- Boot ---------- */
async function boot() {
  initTooltips();

  document.querySelector(".skip-link").addEventListener("click", (e) => {
    // The hash belongs to the router, so the skip link moves focus manually.
    e.preventDefault();
    const main = document.getElementById("main") || document.getElementById("app");
    main.setAttribute("tabindex", "-1");
    main.focus();
  });

  mount(document.getElementById("app"), h("div", { class: "boot", role: "status" }, logoMark(40), h("span", { class: "sr-only" }, "Loading MalDetect")));

  const [me] = await Promise.allSettled([api.me(), refreshHealth()]);
  if (me.status === "fulfilled" && me.value && me.value.user) state.user = me.value.user;

  window.addEventListener("hashchange", render);
  render();
}

boot();
