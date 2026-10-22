import type {
  AttackGraph,
  AttackPath,
  DashboardStats,
  DetectionFinding,
  FilterCategory,
  InvestigationSummary,
  NodeDetail,
  NormalizedEvent,
  PathSearchResult,
  RankedEntity,
  ReplayResult,
  ReplayScenario,
} from "./types";

const BASE = "/api";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<{ status: string; ready: boolean }>("/health"),
  stats: () => get<DashboardStats>("/stats"),
  graph: (params?: Record<string, string | number | undefined | null>) => {
    const q = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
      });
    }
    const qs = q.toString();
    return get<AttackGraph>(`/graph${qs ? `?${qs}` : ""}`);
  },
  events: (params?: Record<string, string | number | undefined>) => {
    const q = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== "") q.set(k, String(v));
      });
    }
    const qs = q.toString();
    return get<NormalizedEvent[]>(`/events${qs ? `?${qs}` : ""}`);
  },
  findings: () => get<DetectionFinding[]>("/findings"),
  paths: () => get<AttackPath[]>("/paths"),
  investigations: () => get<InvestigationSummary[]>("/investigations"),
  rankUsers: (offset = 0, limit = 8) =>
    get<RankedEntity[]>(`/rankings/users?offset=${offset}&limit=${limit}`),
  rankHosts: (offset = 0, limit = 8) =>
    get<RankedEntity[]>(`/rankings/hosts?offset=${offset}&limit=${limit}`),
  filters: () => get<FilterCategory[]>("/filters/categories"),
  nodeDetail: (id: string) => get<NodeDetail>(`/nodes/${encodeURIComponent(id)}`),
  searchPath: (source: string, target: string) =>
    post<PathSearchResult>("/search/path", { source, target, max_hops: 6 }),
  filter: (field: string, value: string) =>
    post<{ event_count: number; graph: AttackGraph }>("/filter", { field, value }),
  scenarios: () => get<ReplayScenario[]>("/scenarios"),
  replay: (id: string) => post<ReplayResult>(`/scenarios/${id}/replay`),
  reload: () => post<{ total_events?: number; findings?: number; status?: string }>("/pipeline/reload"),
  upload: async (file: File, replace = false) => {
    const body = new FormData();
    body.append("file", file);
    body.append("replace", String(replace));
    const res = await fetch(`${BASE}/ingest/upload`, { method: "POST", body });
    if (!res.ok) throw new Error(await res.text());
    return res.json() as Promise<{
      ingested: number;
      total_events: number;
      findings: number;
      paths: number;
    }>;
  },
  ingestPath: (path: string, replace = false) =>
    post<{
      ingested: number;
      total_events: number;
      findings: number;
      paths: number;
    }>("/ingest/path", { path, replace }),
  clearIngest: () =>
    fetch(`${BASE}/ingest/clear`, { method: "DELETE" }).then(async (res) => {
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }),
  batches: () => get<Array<{ id: number; source_file: string; event_count: number; created_at: string }>>("/ingest/batches"),
};
