// Axios client for the HYRON AI backend.
// In development Vite proxies /api and /health to FastAPI (vite.config.js).
// No credentials ever live in the browser: GitHub and AI keys stay server-side.
import axios from "axios";

const WORKSPACE_KEY = "hyron.workspace";

function newWorkspaceId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// A random per-browser workspace ID scopes scan results on the server.
// It is an isolation identifier, not a login - see Settings.
let workspaceId = null;
export function getWorkspaceId() {
  if (workspaceId) return workspaceId;
  try {
    workspaceId = localStorage.getItem(WORKSPACE_KEY);
  } catch {
    workspaceId = null;
  }
  if (!workspaceId || !/^[A-Za-z0-9-]{16,64}$/.test(workspaceId)) {
    workspaceId = newWorkspaceId();
    try {
      localStorage.setItem(WORKSPACE_KEY, workspaceId);
    } catch {
      /* private mode: keep it in memory for this tab */
    }
  }
  return workspaceId;
}

export function resetWorkspaceId() {
  workspaceId = newWorkspaceId();
  try {
    localStorage.setItem(WORKSPACE_KEY, workspaceId);
  } catch {
    /* ignore */
  }
  return workspaceId;
}

// Production uses same-origin Vercel rewrites so browser privacy tools never
// need to contact the Render hostname directly. Development may still opt out
// of the local Vite proxy by setting VITE_API_BASE.
const apiBase = import.meta.env.DEV ? (import.meta.env.VITE_API_BASE ?? "") : "";
const http = axios.create({ baseURL: apiBase, timeout: 180_000 });

http.interceptors.request.use((config) => {
  config.headers["X-Workspace-Id"] = getWorkspaceId();
  return config;
});

export function errorMessage(error) {
  if (!error?.response) {
    if (error?.code === "ECONNABORTED") return "The request timed out. The backend may still be working - check Scan History.";
    return "Cannot reach the HYRON AI backend. Is it running on port 8000?";
  }
  const detail = error.response.data?.detail;
  if (typeof detail === "string") return detail;
  if (detail?.message) {
    // Parser messages usually start with the file name already; don't print it twice.
    const issues = (detail.issues ?? []).filter((i) => i.level === "error")
      .map((i) => (i.message.startsWith(`${i.file}:`) ? i.message : `${i.file}: ${i.message}`));
    return issues.length ? `${detail.message} - ${issues.join(" | ")}` : detail.message;
  }
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return `Request failed (HTTP ${error.response.status})`;
}

const data = (p) => p.then((r) => r.data);

export const api = {
  health: () => data(http.get("/health")),
  meta: () => data(http.get("/api/meta")),
  scans: () => data(http.get("/api/scans")),
  report: (id) => data(http.get(`/api/reports/${encodeURIComponent(id)}`)),
  graph: (id) => data(http.get(`/api/graph/${encodeURIComponent(id)}`)),
  demo: () => data(http.post("/api/demo")),
  upload: (files, onProgress) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    return data(http.post("/api/scan", form, {
      onUploadProgress: (e) => onProgress?.(e.total ? Math.round((e.loaded / e.total) * 100) : null),
    }));
  },
  validateRepo: (url, branch) => data(http.post("/api/repositories/validate", { url, branch: branch || null })),
  scanRepo: (url, branch) => data(http.post("/api/scan/repository", { url, branch: branch || null })),
  scanWebsite: (url) => data(http.post("/api/scan/website", { url, acknowledge_passive: true })),
  explain: (id, findingId) => data(http.post(`/api/reports/${encodeURIComponent(id)}/explain`, { finding_id: findingId ?? null })),
  setStatus: (id, stepKey, status, confirm = false, note = "") =>
    data(http.post(`/api/reports/${encodeURIComponent(id)}/remediation/status`, { step_key: stepKey, status, confirm, note })),
  prDraft: (id, stepKey) => data(http.post(`/api/reports/${encodeURIComponent(id)}/remediation/pr-draft`, { step_key: stepKey })),
  exportUrl: (id) => `/api/reports/${encodeURIComponent(id)}/export`,
  exportJson: (id) => data(http.get(`/api/reports/${encodeURIComponent(id)}/export`)),
};
