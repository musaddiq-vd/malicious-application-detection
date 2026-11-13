// Sign in / create account: one split-screen page, two modes.

import { api } from "../api.js";
import { h, s, mount } from "../dom.js";
import { icon, logoMark } from "../icons.js";
import { themeToggle } from "../ui.js";

const PASSWORD_RULES = [
  { id: "len", label: "At least 8 characters", test: (v) => v.length >= 8 },
  { id: "letter", label: "Contains a letter", test: (v) => /[A-Za-z]/.test(v) },
  { id: "digit", label: "Contains a digit", test: (v) => /\d/.test(v) },
];

const FIELD_DEFS = {
  full_name: { label: "Full name", type: "text", autocomplete: "name", placeholder: "Ada Lovelace", minLength: 2, maxLength: 80 },
  email: { label: "Email", type: "email", autocomplete: "email", placeholder: "you@company.com" },
  username: { label: "Username", type: "text", autocomplete: "username", placeholder: "analyst", maxLength: 32 },
  password: { label: "Password", type: "password" },
};

function clientValidate(mode, values) {
  const errors = {};
  if (mode === "register") {
    if (values.full_name.trim().length < 2) errors.full_name = "Enter your name (2–80 characters).";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email.trim())) errors.email = "Enter a valid email address.";
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(values.username)) errors.username = "Use 3–32 letters, digits, dots, dashes or underscores.";
    if (!PASSWORD_RULES.every((r) => r.test(values.password))) errors.password = "The password does not meet the requirements below.";
  } else {
    if (!values.username.trim()) errors.username = "Enter your username.";
    if (!values.password) errors.password = "Enter your password.";
  }
  return errors;
}

/** Static illustration of a scan result, drawn to match the real result screen. */
function pitchPreview() {
  const r = 54;
  const len = Math.PI * r;
  const arc = `M16 70 A${r} ${r} 0 0 1 124 70`;
  const bars = [
    ["Send SMS", 0.82, true],
    ["Aborts broadcasts", 0.64, true],
    ["Reads device ID", 0.41, true],
    ["Camera", 0.22, false],
  ];
  return h(
    "div",
    { class: "pitch-preview", "aria-hidden": "true" },
    h(
      "div",
      { class: "pitch-preview-head" },
      h("span", { class: "badge badge-malicious" }, icon("shield-alert"), "Malicious"),
      h("span", { class: "mono faint" }, "quickloan-wallet.apk"),
    ),
    h(
      "div",
      { class: "pitch-preview-body" },
      s(
        "svg",
        { viewBox: "0 0 140 84", class: "pitch-gauge" },
        s("path", { d: arc, fill: "none", stroke: "var(--surface-3)", "stroke-width": 10, "stroke-linecap": "round" }),
        s("path", { d: arc, fill: "none", stroke: "var(--mal)", "stroke-width": 10, "stroke-linecap": "round", "stroke-dasharray": `${len * 0.93} ${len}` }),
        s("text", { x: 70, y: 62, "text-anchor": "middle", class: "pitch-gauge-num" }, "93%"),
        s("text", { x: 70, y: 78, "text-anchor": "middle", class: "pitch-gauge-cap" }, "malicious probability"),
      ),
      h(
        "div",
        { class: "pitch-bars" },
        bars.map(([label, w, mal]) =>
          h(
            "div",
            { class: "pitch-bar" },
            h("span", null, label),
            h("i", { class: mal ? "is-mal" : "is-ben", style: { width: `${w * 100}%` } }),
          ),
        ),
      ),
    ),
  );
}

function pitch() {
  const points = [
    ["scan", "Scan an APK or describe an app", "Upload a package for static analysis, or toggle the 35 indicators by hand."],
    ["insights", "See why, not just what", "Every verdict lists the features that pushed the score up or down."],
    ["target", "Honest model metrics", "Evaluated on de-duplicated data, with the leaky legacy baseline shown side by side."],
  ];
  return h(
    "section",
    { class: "auth-pitch" },
    h("div", { class: "auth-brand" }, logoMark(30), h("span", { class: "brand-name" }, "Mal", h("b", null, "Detect"))),
    h(
      "div",
      { class: "auth-pitch-main" },
      h("div", { class: "eyebrow" }, "Android malware detection"),
      h("h1", null, "Know what an app can do before it runs."),
      h("p", { class: "auth-lede" }, "MalDetect reads an app’s static features – permissions, API calls, intents – and returns a risk score you can explain."),
      pitchPreview(),
      h(
        "ul",
        { class: "auth-points" },
        points.map(([ic, title, text]) => h("li", null, h("span", { class: "auth-point-icon" }, icon(ic)), h("div", null, h("strong", null, title), h("span", null, text)))),
      ),
    ),
    h("p", { class: "auth-foot faint" }, "Static analysis only. A benign verdict is a risk estimate, not a guarantee."),
  );
}

export function authView({ mode, onAuthenticated }) {
  const isRegister = mode === "register";
  const fieldNames = isRegister ? ["full_name", "email", "username", "password"] : ["username", "password"];
  const inputs = {};
  const errorSlots = {};

  const formError = h("div", { class: "form-error-slot", "aria-live": "assertive" });
  const submit = h("button", { type: "submit", class: "btn btn-primary btn-lg btn-block" }, isRegister ? "Create account" : "Sign in");

  const setFieldError = (name, message) => {
    const input = inputs[name];
    const slot = errorSlots[name];
    if (!input || !slot) return false;
    if (message) {
      input.setAttribute("aria-invalid", "true");
      mount(slot, h("div", { class: "field-error" }, icon("alert"), h("span", null, message)));
    } else {
      input.removeAttribute("aria-invalid");
      mount(slot);
    }
    return true;
  };

  const setFormError = (message) => {
    mount(formError, message ? h("div", { class: "alert", role: "alert" }, icon("alert"), h("span", null, message)) : null);
  };

  // Live password checklist (register only).
  const ruleItems = PASSWORD_RULES.map((rule) => ({ rule, el: h("li", null, icon("minus"), h("span", null, rule.label)) }));
  const paintRules = (value) => {
    for (const { rule, el } of ruleItems) {
      const ok = rule.test(value);
      el.classList.toggle("is-met", ok);
      el.replaceChild(icon(ok ? "check" : "minus"), el.firstChild);
    }
  };

  const buildField = (name) => {
    const def = FIELD_DEFS[name];
    const id = `auth-${name}`;
    const isPassword = name === "password";
    const input = h("input", {
      class: "input",
      id,
      name,
      type: def.type,
      required: true,
      placeholder: def.placeholder || null,
      autocomplete: isPassword ? (isRegister ? "new-password" : "current-password") : def.autocomplete,
      maxLength: def.maxLength || null,
      spellcheck: "false",
      autocapitalize: name === "full_name" ? "words" : "none",
      "aria-describedby": `${id}-error${isPassword && isRegister ? " auth-password-rules" : ""}`,
    });
    inputs[name] = input;
    errorSlots[name] = h("div", { id: `${id}-error` });
    input.addEventListener("input", () => {
      setFieldError(name, null);
      if (isPassword && isRegister) paintRules(input.value);
    });

    let control = input;
    if (isPassword) {
      const toggle = h("button", { type: "button", class: "input-action", "aria-label": "Show password", "aria-pressed": "false" }, icon("eye"));
      toggle.addEventListener("click", () => {
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        toggle.setAttribute("aria-pressed", String(show));
        toggle.setAttribute("aria-label", show ? "Hide password" : "Show password");
        mount(toggle, icon(show ? "eye-off" : "eye"));
      });
      control = h("div", { class: "input-wrap" }, input, toggle);
    }

    return h(
      "div",
      { class: "field" },
      h("label", { class: "label", for: id }, def.label),
      control,
      errorSlots[name],
      isPassword && isRegister ? h("ul", { class: "pw-rules", id: "auth-password-rules", "aria-label": "Password requirements" }, ruleItems.map((r) => r.el)) : null,
    );
  };

  const form = h("form", { class: "auth-form", novalidate: true }, formError, fieldNames.map(buildField), submit);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setFormError(null);
    const values = Object.fromEntries(fieldNames.map((n) => [n, inputs[n].value]));
    fieldNames.forEach((n) => setFieldError(n, null));

    const clientErrors = clientValidate(mode, values);
    const firstBad = fieldNames.find((n) => clientErrors[n]);
    if (firstBad) {
      fieldNames.forEach((n) => setFieldError(n, clientErrors[n]));
      inputs[firstBad].focus();
      return;
    }

    submit.classList.add("is-loading");
    submit.disabled = true;
    try {
      const body = isRegister
        ? { full_name: values.full_name.trim(), email: values.email.trim(), username: values.username, password: values.password }
        : { username: values.username.trim(), password: values.password };
      const res = isRegister ? await api.register(body) : await api.login(body);
      onAuthenticated(res.user);
    } catch (err) {
      submit.classList.remove("is-loading");
      submit.disabled = false;
      let placed = false;
      for (const fe of err.errors || []) {
        // Field paths may arrive as "password" or "body.password"; match on the last segment.
        const key = fe.field.split(".").pop();
        placed = setFieldError(key, fe.message) || placed;
      }
      if (!placed && err.status === 409) {
        const lower = err.message.toLowerCase();
        if (lower.includes("username")) placed = setFieldError("username", err.message);
        else if (lower.includes("email")) placed = setFieldError("email", err.message);
      }
      if (!placed) setFormError(err.message || "Something went wrong. Please try again.");
      const firstInvalid = form.querySelector("[aria-invalid='true']");
      if (firstInvalid) firstInvalid.focus();
    }
  });

  const panel = h(
    "section",
    { class: "auth-panel" },
    h("div", { class: "auth-panel-top" }, h("div", { class: "auth-brand auth-brand-mobile" }, logoMark(26), h("span", { class: "brand-name" }, "Mal", h("b", null, "Detect"))), themeToggle()),
    h(
      "div",
      { class: "auth-card" },
      h(
        "div",
        { class: "seg seg-lg auth-tabs", role: "tablist", "aria-label": "Account" },
        h("a", { class: "seg-btn", href: "#/login", role: "tab", "aria-selected": String(!isRegister) }, "Sign in"),
        h("a", { class: "seg-btn", href: "#/register", role: "tab", "aria-selected": String(isRegister) }, "Create account"),
      ),
      h("h2", { class: "auth-title" }, isRegister ? "Create your account" : "Welcome back"),
      h("p", { class: "auth-sub muted" }, isRegister ? "Scans and history are private to your account." : "Sign in to run scans and review your history."),
      form,
      h(
        "p",
        { class: "auth-switch muted" },
        isRegister ? "Already have an account? " : "New to MalDetect? ",
        h("a", { href: isRegister ? "#/login" : "#/register" }, isRegister ? "Sign in" : "Create an account"),
      ),
    ),
  );

  const view = h("div", { class: "auth" }, pitch(), h("main", { class: "auth-main", id: "main" }, panel));
  // Focus after insertion so the first field is ready to type into.
  requestAnimationFrame(() => inputs[fieldNames[0]] && inputs[fieldNames[0]].focus());
  return view;
}
