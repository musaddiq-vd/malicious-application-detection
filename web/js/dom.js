// DOM construction helpers. Strings always become text nodes, so API and
// user-supplied values (app names, APK strings) can never be parsed as markup.

const SVG_NS = "http://www.w3.org/2000/svg";

function append(parent, child) {
  if (child === null || child === undefined || child === false || child === true) return;
  if (Array.isArray(child)) {
    for (const c of child) append(parent, c);
    return;
  }
  parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
}

function applyProps(el, props, isSvg) {
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "innerHTML" || key === "outerHTML") throw new Error("Markup injection is not allowed");
    if (key === "class") {
      el.setAttribute("class", Array.isArray(value) ? value.filter(Boolean).join(" ") : value);
    } else if (key === "style" && typeof value === "object") {
      for (const [prop, v] of Object.entries(value)) {
        if (prop.startsWith("--")) el.style.setProperty(prop, v);
        else el.style[prop] = v;
      }
    } else if (key === "dataset") {
      Object.assign(el.dataset, value);
    } else if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (!isSvg && key in el && !key.startsWith("aria") && key !== "list" && key !== "form" && key !== "spellcheck") {
      el[key] = value;
    } else {
      el.setAttribute(key, value === true ? "" : String(value));
    }
  }
}

/** Create an HTML element: h("a", {class: "btn", href: "#/"}, "Home"). */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) applyProps(el, props, false);
  append(el, children);
  return el;
}

/** Create an SVG element. */
export function s(tag, props, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  if (props) applyProps(el, props, true);
  append(el, children);
  return el;
}

export function clear(el) {
  el.replaceChildren();
  return el;
}

export function mount(el, ...children) {
  el.replaceChildren();
  append(el, children);
  return el;
}

export function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

export const prefersReducedMotion = () =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;
