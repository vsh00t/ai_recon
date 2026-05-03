"use client";

const BASE = "/api/v1";

export class ApiError extends Error {
  constructor(public status: number, message: string, public data?: unknown) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: "include",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (!res.ok) {
    let detail: unknown = null;
    try {
      detail = await res.json();
    } catch {}
    throw new ApiError(res.status, res.statusText, detail);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") ?? "";
  return ct.includes("json") ? ((await res.json()) as T) : ((await res.text()) as unknown as T);
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b),
  put: <T>(p: string, b?: unknown) => request<T>("PUT", p, b),
  del: <T>(p: string) => request<T>("DELETE", p),
};

// ---- typed wrappers ----

export interface User {
  id: string;
  email: string;
  role: string;
  created_at: string;
  last_login_at: string | null;
}

export interface Technique {
  id: string;
  kind: string;
  intrusiveness: string;
  requires: string[];
  produces: string[];
  doc: string;
  module: string;
  class_name: string;
}

export interface ProfileSummary {
  name: string;
  source: "builtin" | "custom";
  description?: string | null;
}

export interface Scope {
  id: string;
  name: string;
  doc: Record<string, unknown>;
}

export interface RunSummary {
  id: string;
  scope_id: string | null;
  profile_name: string;
  status: string;
  intrusiveness: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
}

export interface RunEvent {
  seq: number | null;
  ts: string;
  type: string;
  payload: Record<string, unknown>;
}

export interface ReportSummary {
  run_id: string;
  profile: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  severity: { critical: number; high: number; medium: number; low: number; info: number };
  findings_total: number;
}

export const apiClient = {
  login: (email: string, password: string) =>
    api.post<User>("/auth/login", { email, password }),
  logout: () => api.post<{ detail: string }>("/auth/logout"),
  me: () => api.get<User>("/auth/me"),

  techniques: () => api.get<Technique[]>("/techniques"),
  technique: (id: string) => api.get<Technique>(`/techniques/${encodeURIComponent(id)}`),

  catalogs: () => api.get<string[]>("/catalogs"),
  catalog: (name: string) => api.get<unknown>(`/catalogs/${name}`),

  profiles: () => api.get<ProfileSummary[]>("/profiles"),
  profile: (name: string) => api.get<{ name: string; source: string; doc: any }>(`/profiles/${name}`),

  adapters: () => api.get<Record<string, string[]>>("/adapters"),

  scopes: () => api.get<Scope[]>("/scopes"),
  scope: (id: string) => api.get<Scope>(`/scopes/${id}`),
  createScope: (name: string, doc: unknown) => api.post<Scope>("/scopes", { name, doc }),
  updateScope: (id: string, name: string, doc: unknown) => api.put<Scope>(`/scopes/${id}`, { name, doc }),
  deleteScope: (id: string) => api.del<{ detail: string }>(`/scopes/${id}`),

  runs: () => api.get<RunSummary[]>("/runs"),
  run: (id: string) => api.get<RunSummary>(`/runs/${id}`),
  createRun: (body: { scope_id: string; profile: string; intrusiveness?: string; options?: any }) =>
    api.post<RunSummary>("/runs", body),
  cancelRun: (id: string) => api.post<{ detail: string }>(`/runs/${id}/cancel`),
  runEvents: (id: string, since = 0) =>
    api.get<RunEvent[]>(`/runs/${id}/events?since_id=${since}`),
  runFindings: (id: string) => api.get<unknown[]>(`/runs/${id}/findings`),

  report: (id: string) => api.get<ReportSummary>(`/reports/${id}`),
  renderReport: (id: string, format: "json" | "md" = "json") =>
    api.get<unknown>(`/reports/${id}/render?format=${format}`),
};
