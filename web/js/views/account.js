// Account settings: profile summary, password change and account deletion.

import { api } from "../api.js";
import { h, mount } from "../dom.js";
import { icon } from "../icons.js";
import { dateShort, initials } from "../format.js";
import { card, confirmDialog, pageHead, toast } from "../ui.js";

/** A labelled password input with an inline error slot. */
function passwordField({ id, label, autocomplete, hint }) {
  const input = h("input", { class: "input", id, type: "password", required: true, autocomplete, maxLength: 256, "aria-describedby": `${id}-error` });
  const slot = h("div", { id: `${id}-error` });
  const setError = (message) => {
    if (message) {
      input.setAttribute("aria-invalid", "true");
      mount(slot, h("div", { class: "field-error" }, icon("alert"), h("span", null, message)));
    } else {
      input.removeAttribute("aria-invalid");
      mount(slot);
    }
  };
  input.addEventListener("input", () => setError(null));
  const el = h("div", { class: "field" }, h("label", { class: "label", for: id }, label), input, slot, hint ? h("p", { class: "hint" }, hint) : null);
  return { el, input, setError };
}

function profileCard(user) {
  const rows = [
    ["Full name", user.full_name],
    ["Username", `@${user.username}`],
    ["Email", user.email],
    ["Member since", dateShort(user.created_at)],
  ];
  return card({
    title: "Profile",
    body: h(
      "div",
      { class: "profile" },
      h("span", { class: "avatar avatar-lg", "aria-hidden": "true" }, initials(user.full_name || user.username)),
      h("dl", { class: "profile-list" }, rows.map(([term, value]) => h("div", null, h("dt", null, term), h("dd", { class: "truncate" }, value || "—")))),
    ),
  });
}

function passwordCard() {
  const current = passwordField({ id: "pw-current", label: "Current password", autocomplete: "current-password" });
  const next = passwordField({ id: "pw-new", label: "New password", autocomplete: "new-password", hint: "At least 8 characters, with a letter and a digit." });
  const confirm = passwordField({ id: "pw-confirm", label: "Confirm new password", autocomplete: "new-password" });
  const submit = h("button", { type: "submit", class: "btn btn-primary" }, "Update password");
  const form = h("form", { class: "form-stack", novalidate: true }, current.el, next.el, confirm.el, h("div", null, submit));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    [current, next, confirm].forEach((f) => f.setError(null));
    if (!current.input.value) return current.setError("Enter your current password.");
    if (next.input.value !== confirm.input.value) return confirm.setError("The two new passwords do not match.");
    submit.disabled = true;
    try {
      await api.changePassword({ current_password: current.input.value, new_password: next.input.value });
      form.reset();
      toast("Password updated. Other devices have been signed out.", { type: "success" });
    } catch (err) {
      if (err.status === 401) return;
      const target = err.status === 403 || err.status === 429 ? current : next;
      target.setError(err.message);
      target.input.focus();
    } finally {
      submit.disabled = false;
    }
  });

  return card({ title: "Password", sub: "Changing your password signs you out on every other device.", body: form });
}

function dangerCard(user, onDeleted) {
  const password = passwordField({ id: "delete-password", label: "Confirm with your password", autocomplete: "current-password" });
  const submit = h("button", { type: "submit", class: "btn btn-danger" }, icon("trash"), "Delete account");
  const form = h("form", { class: "form-stack", novalidate: true }, password.el, h("div", null, submit));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    password.setError(null);
    if (!password.input.value) return password.setError("Enter your password to continue.");
    const confirmed = await confirmDialog({
      title: "Delete your account?",
      message: `This permanently removes @${user.username} and every scan in its history. It cannot be undone.`,
      confirmLabel: "Delete account",
      danger: true,
    });
    if (!confirmed) return;
    submit.disabled = true;
    try {
      await api.deleteAccount({ password: password.input.value });
      onDeleted();
    } catch (err) {
      if (err.status === 401) return;
      password.setError(err.message);
      password.input.focus();
    } finally {
      submit.disabled = false;
    }
  });

  return card({ title: "Delete account", sub: "Permanently remove your account and all of your scan history.", cls: "card-danger", body: form });
}

export function accountView({ user, onAccountDeleted }) {
  return h(
    "div",
    { class: "view" },
    h(
      "div",
      { class: "page page-narrow" },
      pageHead({ eyebrow: "Account", title: "Account settings", sub: "Manage your sign-in details and your data." }),
      profileCard(user),
      passwordCard(),
      dangerCard(user, onAccountDeleted),
    ),
  );
}
