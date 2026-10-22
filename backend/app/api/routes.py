"""REST API routes for LateralX."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile

from app.config import get_settings
from app.db import clear_events, event_count, list_batches, load_events
from app.engine.graph_builder import search_paths
from app.engine.normalizer import filter_events, logon_type_name
from app.engine.pipeline import empty_pipeline, replay_scenario, run_pipeline
from app.ingest.service import ingest_bytes, ingest_path, reload_from_db
from app.models.schemas import (
    AttackGraph,
    AttackPath,
    DashboardStats,
    DetectionFinding,
    FilterQuery,
    InvestigationSummary,
    NormalizedEvent,
    PathSearchRequest,
    PathSearchResult,
    RankedEntity,
    ReplayResult,
    ReplayScenario,
)
from app.store import store

router = APIRouter()


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "ready": store.ready,
        "service": "LateralX",
        "events": event_count(),
    }


@router.get("/stats", response_model=DashboardStats)
def get_stats() -> DashboardStats:
    _ensure_ready()
    assert store.stats is not None
    return store.stats


@router.get("/graph", response_model=AttackGraph)
def get_graph(
    field: Optional[str] = None,
    value: Optional[str] = None,
    category: Optional[str] = None,
    logon_type: Optional[int] = None,
    label: Optional[str] = None,
) -> AttackGraph:
    _ensure_ready()
    assert store.graph is not None
    if not field and not value and not category and logon_type is None and not label:
        return store.graph

    filtered = filter_events(
        store.events,
        field=field,
        value=value,
        category=category,
        logon_type=logon_type,
        labels=[label] if label else None,
    )
    from app.engine.graph_builder import build_attack_graph

    graph, _ = build_attack_graph(filtered)
    return graph


@router.get("/events", response_model=list[NormalizedEvent])
def list_events(
    field: Optional[str] = Query(default=None),
    value: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    logon_type: Optional[int] = Query(default=None),
    label: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=5000),
) -> list[NormalizedEvent]:
    _ensure_ready()
    labels = [label] if label else None
    filtered = filter_events(
        store.events,
        field=field,
        value=value,
        category=category,
        logon_type=logon_type,
        labels=labels,
    )
    return filtered[:limit]


@router.get("/events/{event_id}", response_model=NormalizedEvent)
def get_event(event_id: str) -> NormalizedEvent:
    _ensure_ready()
    for e in store.events:
        if e.event_id == event_id:
            return e
    raise HTTPException(404, "Event not found")


@router.get("/findings", response_model=list[DetectionFinding])
def list_findings() -> list[DetectionFinding]:
    _ensure_ready()
    return store.findings


@router.get("/findings/{finding_id}", response_model=DetectionFinding)
def get_finding(finding_id: str) -> DetectionFinding:
    _ensure_ready()
    for f in store.findings:
        if f.id == finding_id:
            return f
    raise HTTPException(404, "Finding not found")


@router.get("/paths", response_model=list[AttackPath])
def list_paths() -> list[AttackPath]:
    _ensure_ready()
    return store.paths


@router.get("/paths/{path_id}", response_model=AttackPath)
def get_path(path_id: str) -> AttackPath:
    _ensure_ready()
    for p in store.paths:
        if p.id == path_id:
            return p
    raise HTTPException(404, "Path not found")


@router.get("/investigations", response_model=list[InvestigationSummary])
def list_investigations() -> list[InvestigationSummary]:
    _ensure_ready()
    return store.investigations


@router.get("/rankings/users", response_model=list[RankedEntity])
def rank_users(offset: int = 0, limit: int = 10) -> list[RankedEntity]:
    _ensure_ready()
    return store.user_rankings[offset : offset + limit]


@router.get("/rankings/hosts", response_model=list[RankedEntity])
def rank_hosts(offset: int = 0, limit: int = 10) -> list[RankedEntity]:
    _ensure_ready()
    return store.host_rankings[offset : offset + limit]


@router.post("/search/path", response_model=PathSearchResult)
def search_path(body: PathSearchRequest) -> PathSearchResult:
    _ensure_ready()
    G = getattr(store, "_nx", None)
    if G is None:
        from app.engine.graph_builder import build_attack_graph

        _, G = build_attack_graph(store.events)
        store._nx = G  # type: ignore[attr-defined]
    paths = search_paths(G, body.source, body.target, body.max_hops)
    edge_ids: list[str] = []
    if store.graph:
        path_pairs = set()
        for p in paths:
            for a, b in zip(p, p[1:]):
                path_pairs.add((a, b))
        for e in store.graph.edges:
            if (e.source, e.target) in path_pairs:
                edge_ids.append(e.id)
    conf = 0.9 if paths else 0.0
    if paths and any(len(p) > 3 for p in paths):
        conf = 0.75
    return PathSearchResult(paths=paths, edges_used=edge_ids, confidence=conf)


@router.post("/filter")
def apply_filter(body: FilterQuery) -> dict[str, Any]:
    _ensure_ready()
    filtered = filter_events(
        store.events,
        field=body.field,
        value=body.value,
        category=body.category,
        logon_type=body.logon_type,
    )
    from app.engine.graph_builder import build_attack_graph

    graph, _ = build_attack_graph(filtered)
    return {
        "event_count": len(filtered),
        "graph": graph.model_dump(mode="json"),
        "sample_events": [e.model_dump(mode="json") for e in filtered[:50]],
    }


@router.get("/filters/categories")
def filter_categories() -> list[dict[str, str]]:
    return [
        {"id": "all", "label": "All Activity", "hint": "Full correlated graph"},
        {"id": "label:SYSTEM", "label": "SYSTEM Privileges", "hint": "Event 4672 / elevated"},
        {"id": "label:ntlm_remote", "label": "NTLM Remote Logon", "hint": "Type 3 remote"},
        {"id": "logon:10", "label": "RDP Logon", "hint": "Logon type 10"},
        {"id": "logon:3", "label": "Network Logon", "hint": "Logon type 3"},
        {"id": "logon:4", "label": "Batch Logon", "hint": "Logon type 4"},
        {"id": "logon:5", "label": "Service Logon", "hint": "Logon type 5"},
        {"id": "label:logon_failure", "label": "Logon Failure", "hint": "Event 4625"},
        {"id": "label:dcsync", "label": "Detect DCSync / DCShadow", "hint": "4662 replication"},
        {"id": "label:add_user", "label": "Add / Delete Users", "hint": "Account changes"},
        {"id": "label:audit_policy_change", "label": "Audit Policy Change", "hint": "Event 4719"},
        {"id": "label:lateral", "label": "Lateral Movement", "hint": "Cross-host edges"},
        {"id": "label:psexec", "label": "Remote Execution", "hint": "PsExec-style"},
        {"id": "diff", "label": "Diff Graph", "hint": "Observed vs inferred"},
    ]


@router.get("/meta/logon-types")
def logon_types() -> dict[int, str]:
    from app.engine.normalizer import LOGON_TYPE_LABELS

    return LOGON_TYPE_LABELS


@router.get("/scenarios", response_model=list[ReplayScenario])
def list_scenarios() -> list[ReplayScenario]:
    _ensure_ready()
    return store.scenarios


@router.post("/scenarios/{scenario_id}/replay", response_model=ReplayResult)
def run_replay(scenario_id: str) -> ReplayResult:
    _ensure_ready()
    return replay_scenario(store, scenario_id)


@router.post("/pipeline/reload")
def reload_pipeline() -> dict[str, Any]:
    return reload_from_db()


@router.post("/ingest/upload")
async def ingest_upload(
    file: UploadFile = File(...),
    replace: bool = Form(False),
) -> dict[str, Any]:
    settings = get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "Empty file")
    safe_name = Path(file.filename or "upload.bin").name
    dest = settings.upload_dir / safe_name
    dest.write_bytes(raw)
    try:
        result = ingest_bytes(raw, filename=safe_name, reanalyze=True, replace=replace)
    except Exception as exc:
        raise HTTPException(400, f"Ingest failed: {exc}") from exc
    return {"status": "ok", **result}


@router.post("/ingest/path")
def ingest_filesystem_path(body: dict[str, Any]) -> dict[str, Any]:
    path = body.get("path")
    if not path:
        raise HTTPException(400, "path is required")
    replace = bool(body.get("replace", False))
    try:
        result = ingest_path(path, reanalyze=True, replace=replace)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"Ingest failed: {exc}") from exc
    return {"status": "ok", **result}


@router.get("/ingest/batches")
def ingest_batches() -> list[dict[str, Any]]:
    return list_batches()


@router.delete("/ingest/clear")
def ingest_clear() -> dict[str, Any]:
    removed = clear_events()
    empty_pipeline(store)
    return {"status": "cleared", "removed": removed}


@router.get("/nodes/{node_id}")
def node_detail(node_id: str) -> dict[str, Any]:
    _ensure_ready()
    assert store.graph is not None
    node = next((n for n in store.graph.nodes if n.id == node_id), None)
    if not node:
        node = next(
            (
                n
                for n in store.graph.nodes
                if node_id.lower() in n.id or node_id.lower() in n.label.lower()
            ),
            None,
        )
    if not node:
        raise HTTPException(404, "Node not found")
    related_events = [
        e
        for e in store.events
        if (e.user and f"user:{e.user.lower()}" == node.id)
        or (e.host and f"host:{e.host.lower()}" == node.id)
        or (e.src_host and f"host:{e.src_host.lower()}" == node.id)
        or (e.dst_host and f"host:{e.dst_host.lower()}" == node.id)
        or (node.label.lower() in (e.user or "").lower())
        or (node.label.lower() == e.host.lower())
    ][:40]
    edges = [e for e in store.graph.edges if e.source == node.id or e.target == node.id]
    return {
        "node": node.model_dump(mode="json"),
        "edges": [e.model_dump(mode="json") for e in edges],
        "events": [e.model_dump(mode="json") for e in related_events],
        "logon_types": {
            e.event_id: logon_type_name(e.logon_type) for e in related_events if e.logon_type
        },
    }


def _ensure_ready() -> None:
    if not store.ready:
        events = load_events()
        run_pipeline(store, events)
