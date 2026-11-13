// Display formatting. Everything tolerates null/NaN so a partial API payload
// renders a dash instead of "NaN%".

const DASH = "–";
const isNum = (v) => typeof v === "number" && Number.isFinite(v);

export function pct(value, digits = 0) {
  return isNum(value) ? `${(value * 100).toFixed(digits)}%` : DASH;
}

export function signedPts(value, digits = 1) {
  if (!isNum(value)) return DASH;
  const pts = value * 100;
  const sign = pts > 0 ? "+" : pts < 0 ? "−" : "";
  return `${sign}${Math.abs(pts).toFixed(digits)}`;
}

export function int(value) {
  return isNum(value) ? Math.round(value).toLocaleString("en-US") : DASH;
}

export function fixed(value, digits = 3) {
  return isNum(value) ? value.toFixed(digits) : DASH;
}

export function bytes(value) {
  if (!isNum(value)) return DASH;
  const units = ["B", "KB", "MB", "GB"];
  let v = value;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 || v >= 100 ? 0 : 1)} ${units[i]}`;
}

function parse(iso) {
  if (!iso) return null;
  // The API returns UTC; treat a missing zone designator as UTC rather than local time.
  const normalised = /[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso.replace(" ", "T")}Z`;
  const d = new Date(normalised);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function dateTime(iso) {
  const d = parse(iso);
  if (!d) return DASH;
  return d.toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export function dateShort(iso) {
  const d = parse(iso);
  return d ? d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : DASH;
}

export function relativeTime(iso) {
  const d = parse(iso);
  if (!d) return DASH;
  const sec = Math.round((Date.now() - d.getTime()) / 1000);
  if (sec < 45) return "just now";
  if (sec < 3600) return `${Math.max(1, Math.round(sec / 60))} min ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)} h ago`;
  if (sec < 86400 * 7) return `${Math.round(sec / 86400)} d ago`;
  return dateShort(iso);
}

/** "2026-11-13" -> "13 Nov" without timezone drift. */
export function dayLabel(dateStr) {
  const [y, m, d] = String(dateStr).split("-").map(Number);
  if (!y || !m || !d) return String(dateStr);
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString("en-GB", {
    day: "numeric", month: "short", timeZone: "UTC",
  });
}

export function initials(name) {
  const parts = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  return (parts[0][0] + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

export const titleCase = (str) => String(str || "").replace(/^./, (c) => c.toUpperCase());

export const plural = (n, one, many = `${one}s`) => `${int(n)} ${n === 1 ? one : many}`;
