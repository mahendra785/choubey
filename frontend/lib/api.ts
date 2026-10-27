/**
 * Typed API client. All requests send cookies (credentials: "include"); state-changing requests echo the
 * csrf_token cookie in X-CSRF-Token (double-submit). A 401 triggers ONE silent refresh-token rotation + retry.
 * Nothing here ever builds HTML: callers render results as React text.
 */
import type {
  AttackInfo, AuditEntry, AuditVerify, DetectorInfo, ExperimentBrief, ExperimentDetail, LabResult, Preset, ResultRow,
  Role, SavedConfig, Stage, TargetInfo, User,
} from "./types";

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

function errorText(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return d.map((x) => (x && typeof x === "object" && "msg" in x ? String((x as { msg: unknown }).msg) : "invalid")).join("; ");
  }
  return fallback;
}

async function raw(method: string, path: string, body?: unknown, retry = true): Promise<Response> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();
  const res = await fetch(API_URL + path, {
    method, headers, credentials: "include", body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && retry && path !== "/auth/login" && path !== "/auth/refresh") {
    const r = await fetch(API_URL + "/auth/refresh", { method: "POST", credentials: "include", headers: { "X-CSRF-Token": csrfToken() } });
    if (r.ok) return raw(method, path, body, false);
  }
  return res;
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await raw(method, path, body);
  if (res.status === 204) return undefined as T;
  let data: unknown = null;
  try { data = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) throw new ApiError(res.status, errorText(data, `Request failed (${res.status})`));
  return data as T;
}

const get = <T,>(p: string) => call<T>("GET", p);
const post = <T,>(p: string, b?: unknown) => call<T>("POST", p, b ?? {});
const patch = <T,>(p: string, b: unknown) => call<T>("PATCH", p, b);
const del = <T,>(p: string) => call<T>("DELETE", p);

export interface ExperimentRequest {
  name: string; kind: "end_to_end" | "conformal_sweep"; targets: string[]; defenses: string[]; include_benign: boolean;
  n_variants: number; max_payloads: number; benign_per_target: number; alphas: number[]; seed: number; categories?: string[] | null;
}
export interface RunRequest {
  target: string; payload_id?: string; custom_text?: string; defense: string; alpha?: number; vector: "direct" | "indirect"; user_query?: string;
}

export const api = {
  login: (email: string, password: string) => post<{ user: User; csrf_token: string }>("/auth/login", { email, password }),
  logout: () => post<void>("/auth/logout"),
  me: () => get<User>("/auth/me"),

  targets: () => get<TargetInfo[]>("/targets"),
  attacks: () => get<AttackInfo[]>("/attacks"),
  runLab: (r: RunRequest) => post<LabResult>("/targets/run", r),

  presets: () => get<Preset[]>("/defenses/presets"),
  detector: () => get<DetectorInfo>("/defenses/detector"),
  configs: () => get<SavedConfig[]>("/defenses/configs"),
  saveConfig: (name: string, stages: Stage[]) => post<SavedConfig>("/defenses/configs", { name, config: { stages } }),
  deleteConfig: (id: string) => del<void>(`/defenses/configs/${id}`),

  experiments: (kind?: string) => get<ExperimentBrief[]>("/experiments" + (kind ? `?kind=${kind}` : "")),
  experiment: (id: string) => get<ExperimentDetail>(`/experiments/${id}`),
  results: (id: string, limit = 50, offset = 0) => get<{ total: number; items: ResultRow[] }>(`/experiments/${id}/results?limit=${limit}&offset=${offset}`),
  createExperiment: (r: ExperimentRequest) => post<ExperimentBrief>("/experiments", r),
  setShared: (id: string, shared: boolean) => patch<ExperimentBrief>(`/experiments/${id}/shared`, { shared }),
  files: (id: string) => get<string[]>(`/experiments/${id}/files`),
  fileUrl: (id: string, name: string) => `${API_URL}/experiments/${id}/files/${encodeURIComponent(name)}`,

  users: () => get<User[]>("/admin/users"),
  createUser: (email: string, password: string, role: Role) => post<User>("/admin/users", { email, password, role }),
  setRole: (id: string, role: Role) => patch<User>(`/admin/users/${id}/role`, { role }),
  setActive: (id: string, is_active: boolean) => patch<User>(`/admin/users/${id}/active`, { is_active }),
  audit: (limit = 100) => get<AuditEntry[]>(`/admin/audit?limit=${limit}`),
  verifyAudit: () => get<AuditVerify>("/admin/audit/verify"),
};
