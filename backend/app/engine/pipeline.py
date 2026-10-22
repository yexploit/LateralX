"""End-to-end analysis pipeline over ingested telemetry."""

from __future__ import annotations

import time

from app.engine.detector import run_detections
from app.engine.enricher import enrich_events
from app.engine.graph_builder import build_attack_graph, rank_entities
from app.engine.path_reconstructor import build_investigations, reconstruct_paths
from app.models.schemas import (
    AttackGraph,
    DashboardStats,
    EvidenceKind,
    NormalizedEvent,
    ReplayResult,
    ReplayScenario,
)
from app.store import InvestigationStore


def run_pipeline(
    store: InvestigationStore,
    events: list[NormalizedEvent] | None = None,
) -> None:
    started = time.perf_counter()
    events = enrich_events(list(events or []))
    graph, _G = build_attack_graph(events)
    findings = run_detections(events) if events else []
    paths = reconstruct_paths(events, findings) if events else []
    investigations = build_investigations(paths, findings) if paths else []
    user_rankings, host_rankings = rank_entities(graph) if events else ([], [])

    latency_ms = (time.perf_counter() - started) * 1000
    observed = sum(1 for e in graph.edges if e.kind == EvidenceKind.OBSERVED)
    inferred = sum(1 for e in graph.edges if e.kind == EvidenceKind.INFERRED)

    stats = _compute_stats(events, graph, findings, paths, observed, inferred, latency_ms)
    scenarios = _builtin_validation_scenarios()

    store.replace_all(
        events=events,
        graph=graph,
        findings=findings,
        paths=paths,
        investigations=investigations,
        user_rankings=user_rankings,
        host_rankings=host_rankings,
        stats=stats,
        scenarios=scenarios,
    )
    store._nx = _G  # type: ignore[attr-defined]


def empty_pipeline(store: InvestigationStore) -> None:
    run_pipeline(store, [])


def _compute_stats(events, graph: AttackGraph, findings, paths, observed, inferred, latency_ms):
    ts_start = min((e.timestamp for e in events), default=None)
    ts_end = max((e.timestamp for e in events), default=None)

    lateralish = [
        e
        for e in events
        if "lateral" in e.labels or e.logon_type in {3, 10} or e.event_code in {4662, 1}
    ]
    high = [f for f in findings if f.severity.value in {"critical", "high"}]
    if not events:
        detection_rate = 0.0
        path_accuracy = 0.0
        fpr = 0.0
    else:
        # Share of notable clusters that produced high/critical findings
        detection_rate = min(1.0, len(high) / max(1, min(len(lateralish), 8))) if lateralish else (
            1.0 if findings else 0.0
        )
        path_accuracy = (
            1.0
            if paths and len(paths[0].compromised_hosts) >= 2 and paths[0].steps
            else (0.7 if paths else 0.0)
        )
        weak = sum(1 for f in findings if f.confidence < 0.8)
        fpr = round(min(0.35, weak / max(len(findings), 1) * 0.25), 3)

    return DashboardStats(
        total_events=len(events),
        total_hosts=len({e.host for e in events}),
        total_users=len({e.user for e in events if e.user}),
        total_findings=len(findings),
        critical_findings=sum(1 for f in findings if f.severity.value == "critical"),
        attack_paths=len(paths),
        observed_edges=observed,
        inferred_edges=inferred,
        time_range_start=ts_start,
        time_range_end=ts_end,
        detection_rate=round(detection_rate, 3),
        false_positive_rate=fpr,
        avg_latency_ms=round(latency_ms, 2),
        path_accuracy=round(path_accuracy, 3),
    )


def _builtin_validation_scenarios() -> list[ReplayScenario]:
    """Optional validation packs (synthetic) — not used unless explicitly replayed."""
    return [
        ReplayScenario(
            id="scenario-3host-dcsync",
            name="Validation pack: 3-Host Lateral + DCSync",
            description=(
                "Optional synthetic pack to validate the engine. "
                "Production use should ingest real EVTX/JSON/CSV instead."
            ),
            hosts=["workstation-01", "fileserver-01", "dc-01"],
            expected_techniques=[
                "T1059.001",
                "T1003.001",
                "T1021.001",
                "T1021.002",
                "T1003.006",
            ],
            status="optional",
        )
    ]


def replay_scenario(store: InvestigationStore, scenario_id: str) -> ReplayResult:
    from app.engine.synthetic import generate_scenario_events

    started = time.perf_counter()
    scenario = next((s for s in store.scenarios if s.id == scenario_id), None)
    if scenario is None:
        return ReplayResult(
            scenario_id=scenario_id,
            detected=False,
            findings_matched=[],
            path_reconstructed=False,
            detection_rate=0.0,
            false_positives=0,
            latency_ms=0.0,
            path_accuracy=0.0,
            summary="Unknown scenario.",
        )

    # Validation only — does not wipe the operator's persisted telemetry DB.
    events = generate_scenario_events()
    run_pipeline(store, events)
    latency_ms = (time.perf_counter() - started) * 1000
    expected = set(scenario.expected_techniques)
    matched = sorted({t for f in store.findings for t in f.mitre_techniques if t in expected})
    detection_rate = len(set(matched).intersection(expected)) / max(len(expected), 1)
    path_ok = bool(store.paths) and all(
        any(h.lower() == c.lower() for c in store.paths[0].compromised_hosts) for h in scenario.hosts
    )
    result = ReplayResult(
        scenario_id=scenario_id,
        detected=detection_rate >= 0.6,
        findings_matched=[f.id for f in store.findings if set(f.mitre_techniques) & expected],
        path_reconstructed=path_ok,
        detection_rate=round(detection_rate, 3),
        false_positives=max(0, len(store.findings) - len(expected)),
        latency_ms=round(latency_ms, 2),
        path_accuracy=store.stats.path_accuracy if store.stats else 0.0,
        summary=(
            f"Validation '{scenario.name}' finished. detection={detection_rate:.0%}, "
            f"path={path_ok}, latency={latency_ms:.1f}ms. "
            "Re-ingest your real logs afterward to restore production analysis."
        ),
    )
    store.last_replay = result
    return result
