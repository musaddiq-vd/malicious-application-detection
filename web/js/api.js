// Thin client for the MalDetect REST API (same-origin, cookie session).

export class ApiError extends Error {
  constructor(status, detail, errors = []) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.errors = errors;
  }
}

let unauthorizedHandler = () => {};

/** Register what happens when a protected call returns 401 (session expired). */
export function onUnauthorized(fn) {
  unauthorizedHandler = fn;
}

function fallbackMessage(status) {
  if (status === 0) return "Cannot reach the server. Check your connection and try again.";
  if (status === 413) return "That file is too large to upload.";
  if (status === 429) return "Too many attempts. Please wait a few minutes and try again.";
  if (status >= 500) return "The server ran into a problem. Please try again.";
  return `Request failed (${status}).`;
}

function toError(status, payload) {
  let detail = payload && payload.detail;
  // Tolerate FastAPI's default list-shaped validation detail if it is ever not flattened.
  if (Array.isArray(detail)) detail = detail[0] && (detail[0].msg || detail[0].message);
  const errors = payload && Array.isArray(payload.errors)
    ? payload.errors.filter((e) => e && e.message).map((e) => ({ field: String(e.field || ""), message: String(e.message) }))
    : [];
  return new ApiError(status, typeof detail === "string" && detail ? detail : fallbackMessage(status), errors);
}

async function request(method, path, { body, guard = true } = {}) {
  let res;
  try {
    res = await fetch(`/api${path}`, {
      method,
      credentials: "same-origin",
      headers: body !== undefined ? { "Content-Type": "application/json", Accept: "application/json" } : { Accept: "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, fallbackMessage(0));
  }
  if (res.status === 204) return null;
  let payload = null;
  try {
    payload = await res.json();
  } catch {
    payload = null;
  }
  if (!res.ok) {
    if (res.status === 401 && guard) unauthorizedHandler();
    throw toError(res.status, payload);
  }
  return payload;
}

/** Multipart upload through XHR because fetch cannot report upload progress. */
function upload(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api${path}`);
    xhr.withCredentials = true;
    xhr.responseType = "text";
    xhr.setRequestHeader("Accept", "application/json");
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
    });
    xhr.addEventListener("load", () => {
      let payload = null;
      try {
        payload = JSON.parse(xhr.responseText);
      } catch {
        payload = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(payload);
      } else {
        if (xhr.status === 401) unauthorizedHandler();
        reject(toError(xhr.status, payload));
      }
    });
    xhr.addEventListener("error", () => reject(new ApiError(0, fallbackMessage(0))));
    xhr.addEventListener("abort", () => reject(new ApiError(0, "Upload cancelled.")));
    const form = new FormData();
    form.append("file", file, file.name);
    xhr.send(form);
  });
}

// The catalog and metrics never change during a session, so fetch them once.
const cache = new Map();
function cached(key, loader) {
  if (!cache.has(key)) {
    cache.set(key, loader().catch((err) => {
      cache.delete(key);
      throw err;
    }));
  }
  return cache.get(key);
}

function query(params) {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") usp.set(k, String(v));
  }
  const str = usp.toString();
  return str ? `?${str}` : "";
}

export const api = {
  health: () => request("GET", "/health", { guard: false }),
  me: () => request("GET", "/auth/me", { guard: false }),
  login: (body) => request("POST", "/auth/login", { body, guard: false }),
  register: (body) => request("POST", "/auth/register", { body, guard: false }),
  logout: () => request("POST", "/auth/logout", { guard: false }),
  features: () => cached("features", () => request("GET", "/features")),
  presets: () => cached("presets", () => request("GET", "/features/presets")),
  metrics: () => cached("metrics", () => request("GET", "/model/metrics")),
  stats: () => request("GET", "/stats"),
  scans: (params = {}) => request("GET", `/scans${query(params)}`),
  scan: (id) => request("GET", `/scans/${encodeURIComponent(id)}`),
  deleteScan: (id) => request("DELETE", `/scans/${encodeURIComponent(id)}`),
  scanManual: (body) => request("POST", "/scans/manual", { body }),
  scanApk: (file, onProgress) => upload("/scans/apk", file, onProgress),
  clearCache: () => cache.clear(),
};
