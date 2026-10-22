import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import { api } from "./api";
import { AttackGraphView } from "./components/AttackGraphView";
import { IngestPanel } from "./components/IngestPanel";
import { NodeTooltip } from "./components/NodeTooltip";
import type {
  AttackGraph,
  AttackPath,
  DashboardStats,
  DetectionFinding,
  FilterCategory,
  GraphNode,
  InvestigationSummary,
  NormalizedEvent,
  RankedEntity,
  ReplayResult,
  ReplayScenario,
} from "./types";

type DockTab = "ingest" | "events" | "findings" | "path" | "investigation" | "replay";
type SearchField = "username" | "host" | "ip" | "process" | "event_code";

function pct(n: number) {
  return `${Math.round(n * 100)}%`;
}

function fmtTime(iso?: string | null) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function App() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [filters, setFilters] = useState<FilterCategory[]>([]);
  const [activeFilter, setActiveFilter] = useState("all");
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [findings, setFindings] = useState<DetectionFinding[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [users, setUsers] = useState<RankedEntity[]>([]);
  const [hosts, setHosts] = useState<RankedEntity[]>([]);
  const [userPage, setUserPage] = useState(0);
  const [hostPage, setHostPage] = useState(0);
  const [scenarios, setScenarios] = useState<ReplayScenario[]>([]);
  const [replayResult, setReplayResult] = useState<ReplayResult | null>(null);
  const [dock, setDock] = useState<DockTab>("ingest");
  const [field, setField] = useState<SearchField>("username");
  const [query, setQuery] = useState("");
  const [pathSource, setPathSource] = useState("");
  const [pathTarget, setPathTarget] = useState("");
  const [highlightPath, setHighlightPath] = useState<string[]>([]);
  const [selected, setSelected] = useState<{
    node: GraphNode;
    x: number;
    y: number;
  } | null>(null);
  const [dark, setDark] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadCore = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, g, fcats, ev, find, p, inv, sc] = await Promise.all([
        api.stats(),
        api.graph(),
        api.filters(),
        api.events({ limit: 120 }),
        api.findings(),
        api.paths(),
        api.investigations(),
        api.scenarios(),
      ]);
      setStats(s);
      setGraph(g);
      setFilters(fcats);
      setEvents(ev);
      setFindings(find);
      setPaths(p);
      setInvestigations(inv);
      setScenarios(sc);
      if ((s?.total_events ?? 0) === 0) setDock("ingest");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load LateralX API");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRankings = useCallback(async () => {
    const [u, h] = await Promise.all([
      api.rankUsers(userPage * 8, 8),
      api.rankHosts(hostPage * 8, 8),
    ]);
    setUsers(u);
    setHosts(h);
  }, [userPage, hostPage]);

  useEffect(() => {
    loadCore();
  }, [loadCore]);

  useEffect(() => {
    loadRankings().catch(() => undefined);
  }, [loadRankings]);

  const applySidebarFilter = async (id: string) => {
    setActiveFilter(id);
    setSelected(null);
    if (id === "all") {
      const g = await api.graph();
      setGraph(g);
      setEvents(await api.events({ limit: 120 }));
      return;
    }
    if (id === "diff") {
      // show full graph; inferred edges already dashed
      const g = await api.graph();
      setGraph(g);
      setDock("path");
      return;
    }
    if (id.startsWith("logon:")) {
      const lt = Number(id.split(":")[1]);
      setGraph(await api.graph({ logon_type: lt }));
      setEvents(await api.events({ logon_type: lt, limit: 120 }));
      return;
    }
    if (id.startsWith("label:")) {
      const label = id.slice("label:".length);
      if (label === "SYSTEM") {
        setEvents(await api.events({ label: "special_privileges", limit: 120 }));
        setGraph(await api.graph({ label: "special_privileges" }));
        return;
      }
      setEvents(await api.events({ label, limit: 120 }));
      setGraph(await api.graph({ label }));
      return;
    }
  };

  const runSearch = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.filter(field, query);
      setGraph(res.graph);
      setEvents(await api.events({ field, value: query, limit: 120 }));
      setDock("events");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Search failed");
    } finally {
      setBusy(false);
    }
  };

  const runPathSearch = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.searchPath(pathSource, pathTarget);
      if (res.paths.length) {
        setHighlightPath(res.paths[0]);
        setDock("path");
      } else {
        setHighlightPath([]);
        setError("No path found between those entities.");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Path search failed");
    } finally {
      setBusy(false);
    }
  };

  const exportJson = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      stats,
      graph,
      findings,
      paths,
      investigations,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `lateralx-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runReplay = async (id: string) => {
    setBusy(true);
    try {
      const result = await api.replay(id);
      setReplayResult(result);
      await loadCore();
      await loadRankings();
      setDock("replay");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Replay failed");
    } finally {
      setBusy(false);
    }
  };

  const primaryPath = paths[0];
  const primaryInv = investigations[0];

  const stageStyle = useMemo(
    () =>
      dark
        ? undefined
        : ({
            filter: "invert(0.92) hue-rotate(180deg)",
          } as CSSProperties),
    [dark]
  );

  if (loading && !graph) {
    return <div className="loading">Initializing LateralX correlation engine…</div>;
  }

  if (error && !graph) {
    return (
      <div className="error">
        <p>{error}</p>
        <p>Start the API: <code className="mono">uvicorn app.main:app --reload</code></p>
        <button className="btn btn-primary" onClick={loadCore}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="app-shell" style={stageStyle}>
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark" aria-hidden />
          <div>
            <h1>LateralX</h1>
            <span>Attack path investigation</span>
          </div>
        </div>

        <div className="search-cluster">
          <select
            className="select"
            value={field}
            onChange={(e) => setField(e.target.value as SearchField)}
          >
            <option value="username">Username</option>
            <option value="host">Host</option>
            <option value="ip">IP</option>
            <option value="process">Process</option>
            <option value="event_code">Event code</option>
          </select>
          <input
            className="field"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter entity…"
            onKeyDown={(e) => e.key === "Enter" && runSearch()}
          />
          <button className="btn" onClick={runSearch} disabled={busy}>
            Filter
          </button>
          <button className="btn" onClick={runSearch} disabled={busy}>
            Search
          </button>
          <input
            className="field"
            style={{ maxWidth: 140 }}
            value={pathSource}
            onChange={(e) => setPathSource(e.target.value)}
            placeholder="Path source"
          />
          <input
            className="field"
            style={{ maxWidth: 140 }}
            value={pathTarget}
            onChange={(e) => setPathTarget(e.target.value)}
            placeholder="Path target"
          />
          <button className="btn btn-primary" onClick={runPathSearch} disabled={busy}>
            Search path
          </button>
          <button className="btn" onClick={exportJson}>
            Export
          </button>
        </div>

        <div className="top-actions">
          <span className="status-pill">Engine live</span>
          <label className="toggle">
            Dark Mode
            <button
              className={`toggle-track ${dark ? "on" : ""}`}
              onClick={() => setDark((d) => !d)}
              aria-label="Toggle dark mode"
              type="button"
            >
              <span className="toggle-thumb" />
            </button>
          </label>
        </div>
      </header>

      <div className="workspace">
        <aside className="panel">
          <div className="panel-title">Detection views</div>
          <div className="filter-list">
            {filters.map((f) => (
              <button
                key={f.id}
                className={`filter-item ${activeFilter === f.id ? "active" : ""}`}
                onClick={() => applySidebarFilter(f.id)}
              >
                <strong>{f.label}</strong>
                <small>{f.hint}</small>
              </button>
            ))}
          </div>
        </aside>

        <main className="stage">
          {stats && (
            <div className="metrics">
              <div className="metric">
                <div className="label">Detection rate</div>
                <div className="value good">{pct(stats.detection_rate)}</div>
              </div>
              <div className="metric">
                <div className="label">False-positive rate</div>
                <div className="value warn">{pct(stats.false_positive_rate)}</div>
              </div>
              <div className="metric">
                <div className="label">Event → alert latency</div>
                <div className="value">{stats.avg_latency_ms.toFixed(1)} ms</div>
              </div>
              <div className="metric">
                <div className="label">Path accuracy</div>
                <div className="value good">{pct(stats.path_accuracy)}</div>
              </div>
            </div>
          )}

          {graph && (
            <AttackGraphView
              graph={graph}
              highlightPath={highlightPath}
              selectedId={selected?.node.id}
              onSelect={(node, coords) => setSelected({ node, ...coords })}
            />
          )}

          {selected && (
            <NodeTooltip
              node={selected.node}
              x={selected.x}
              y={selected.y}
              onClose={() => setSelected(null)}
              onSearch={() => {
                setField(selected.node.type === "host" ? "host" : "username");
                setQuery(selected.node.label);
                setSelected(null);
                void (async () => {
                  const f = selected.node.type === "host" ? "host" : "username";
                  const res = await api.filter(f, selected.node.label);
                  setGraph(res.graph);
                  setEvents(await api.events({ field: f, value: selected.node.label, limit: 120 }));
                  setDock("events");
                })();
              }}
            />
          )}

          <section className="bottom-dock">
            <div className="tabs">
              {(
                [
                  ["ingest", "Ingest"],
                  ["path", "Attack path"],
                  ["findings", "Findings"],
                  ["events", "Evidence"],
                  ["investigation", "Investigation"],
                  ["replay", "Validation pack"],
                ] as [DockTab, string][]
              ).map(([id, label]) => (
                <button
                  key={id}
                  className={`tab ${dock === id ? "active" : ""}`}
                  onClick={() => setDock(id)}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="dock-body">
              {error && <div className="error" style={{ padding: "0.4rem 0" }}>{error}</div>}

              {dock === "ingest" && <IngestPanel onChanged={loadCore} />}

              {dock === "events" && (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Code</th>
                      <th>Host</th>
                      <th>User</th>
                      <th>Detail</th>
                      <th>Labels</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((e) => (
                      <tr key={e.event_id} id={`event-${e.event_id}`}>
                        <td className="mono">{fmtTime(e.timestamp)}</td>
                        <td className="mono">{e.event_code}</td>
                        <td>{e.host}</td>
                        <td>{e.user || "—"}</td>
                        <td>
                          {e.process_name || e.command_line || e.status || e.category}
                        </td>
                        <td>
                          {e.labels.slice(0, 3).map((l) => (
                            <span key={l} className="badge observed" style={{ marginRight: 4 }}>
                              {l}
                            </span>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {dock === "findings" &&
                findings.map((f) => (
                  <article key={f.id} className="finding-card" id={`finding-${f.id}`}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
                      <span className={`badge ${f.severity}`}>{f.severity}</span>
                      <span className={`badge ${f.kind}`}>{f.kind}</span>
                      <span className="mono" style={{ color: "var(--text-mute)", fontSize: 12 }}>
                        {f.rule_id} · {pct(f.confidence)}
                      </span>
                    </div>
                    <h4>{f.title}</h4>
                    <p>{f.description}</p>
                    <p style={{ marginTop: 6 }}>
                      MITRE: {f.mitre_techniques.join(", ") || "—"} · Hosts: {f.hosts.join(", ")}
                    </p>
                  </article>
                ))}

              {dock === "path" && !primaryPath && (
                <div className="empty">No attack path yet. Ingest Windows/Sysmon logs first.</div>
              )}

              {dock === "path" && primaryPath && (
                <div className="path-card">
                  <div style={{ display: "flex", gap: 8, marginBottom: 6 }}>
                    <span className={`badge ${primaryPath.severity}`}>{primaryPath.severity}</span>
                    <span className="mono" style={{ color: "var(--text-mute)", fontSize: 12 }}>
                      confidence {pct(primaryPath.confidence)}
                    </span>
                  </div>
                  <h4>{primaryPath.name}</h4>
                  <p>{primaryPath.summary}</p>
                  <div className="timeline">
                    {primaryPath.steps.map((s) => (
                      <div className="tl-step" key={s.step}>
                        <div className="tl-num">{s.step}</div>
                        <div className="tl-body">
                          <strong>
                            {s.action}{" "}
                            <span className={`badge ${s.kind}`}>{s.kind}</span>
                          </strong>
                          <div>{s.detail}</div>
                          <div className="tl-meta">
                            {fmtTime(s.timestamp)} · {s.host}
                            {s.user ? ` · ${s.user}` : ""}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <h4 style={{ marginTop: 12 }}>Recommended response</h4>
                  <ul>
                    {primaryPath.recommended_response.map((r) => (
                      <li key={r} style={{ color: "var(--text-dim)", fontSize: "0.84rem" }}>
                        {r}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {dock === "investigation" && primaryInv && (
                <div className="inv-card">
                  <h4>{primaryInv.title}</h4>
                  <p>{primaryInv.narrative}</p>
                  <div style={{ marginTop: 10 }}>
                    <strong>Evidence links</strong>
                    <ul>
                      {primaryInv.evidence_links.map((l, i) => (
                        <li key={i}>
                          <a href={l.href}>{l.label}</a>
                          {l.kind ? (
                            <span className={`badge ${l.kind}`} style={{ marginLeft: 6 }}>
                              {l.kind}
                            </span>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {dock === "replay" && (
                <div>
                  {scenarios.map((s) => (
                    <div className="path-card" key={s.id}>
                      <h4>{s.name}</h4>
                      <p>{s.description}</p>
                      <p style={{ marginTop: 6 }} className="mono">
                        Hosts: {s.hosts.join(" → ")}
                      </p>
                      <div className="list-actions">
                        <button
                          className="btn btn-primary"
                          disabled={busy}
                          onClick={() => runReplay(s.id)}
                        >
                          Replay scenario
                        </button>
                      </div>
                    </div>
                  ))}
                  {replayResult && (
                    <div className="path-card">
                      <h4>Last replay result</h4>
                      <p>{replayResult.summary}</p>
                      <p className="mono" style={{ marginTop: 8 }}>
                        detected={String(replayResult.detected)} · rate{" "}
                        {pct(replayResult.detection_rate)} · path=
                        {String(replayResult.path_reconstructed)} · latency{" "}
                        {replayResult.latency_ms.toFixed(1)} ms · accuracy{" "}
                        {pct(replayResult.path_accuracy)}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>
        </main>

        <aside className="panel panel-right">
          <div className="panel-title">Entity ranking</div>
          <div className="rank-block">
            <h3>Users</h3>
            {users.map((u) => (
              <div
                className="rank-row"
                key={u.id}
                onClick={() => {
                  setField("username");
                  setQuery(u.label);
                  void api.filter("username", u.label).then(async (res) => {
                    setGraph(res.graph);
                    setEvents(await api.events({ field: "username", value: u.label, limit: 120 }));
                    setDock("events");
                  });
                }}
              >
                <span className="idx">{u.rank}</span>
                <span className="name">
                  {u.label}
                  {u.privilege ? ` · ${u.privilege}` : ""}
                </span>
                <span className="score">{u.score.toFixed(1)}</span>
              </div>
            ))}
            <div className="pager">
              <button
                className="btn"
                disabled={userPage === 0}
                onClick={() => setUserPage((p) => Math.max(0, p - 1))}
              >
                Back
              </button>
              <button className="btn" onClick={() => setUserPage((p) => p + 1)}>
                Next
              </button>
            </div>
          </div>

          <div className="rank-block">
            <h3>Hosts</h3>
            {hosts.map((h) => (
              <div
                className="rank-row"
                key={h.id}
                onClick={() => {
                  setField("host");
                  setQuery(h.label);
                  void api.filter("host", h.label).then(async (res) => {
                    setGraph(res.graph);
                    setEvents(await api.events({ field: "host", value: h.label, limit: 120 }));
                    setDock("events");
                  });
                }}
              >
                <span className="idx">{h.rank}</span>
                <span className="name">{h.label}</span>
                <span className="score">{h.score.toFixed(1)}</span>
              </div>
            ))}
            <div className="pager">
              <button
                className="btn"
                disabled={hostPage === 0}
                onClick={() => setHostPage((p) => Math.max(0, p - 1))}
              >
                Back
              </button>
              <button className="btn" onClick={() => setHostPage((p) => p + 1)}>
                Next
              </button>
            </div>
          </div>

          {stats && (
            <div className="rank-block">
              <h3>Corpus</h3>
              <p style={{ color: "var(--text-dim)", fontSize: "0.8rem", margin: 0 }}>
                {stats.total_events} events · {stats.total_hosts} hosts · {stats.total_users} users
                · {stats.total_findings} findings ({stats.critical_findings} critical)
              </p>
              <p
                className="mono"
                style={{ color: "var(--text-mute)", fontSize: "0.72rem", marginTop: 8 }}
              >
                {fmtTime(stats.time_range_start)} → {fmtTime(stats.time_range_end)}
              </p>
              <p style={{ color: "var(--text-dim)", fontSize: "0.78rem", marginTop: 8 }}>
                Edges: {stats.observed_edges} observed / {stats.inferred_edges} inferred
              </p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
