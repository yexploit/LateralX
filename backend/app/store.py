"""In-memory investigation store — seeded from synthetic telemetry on startup."""

from __future__ import annotations

from threading import RLock
from typing import Optional

from app.models.schemas import (
    AttackGraph,
    AttackPath,
    DashboardStats,
    DetectionFinding,
    InvestigationSummary,
    NormalizedEvent,
    RankedEntity,
    ReplayResult,
    ReplayScenario,
)


class InvestigationStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self.events: list[NormalizedEvent] = []
        self.graph: Optional[AttackGraph] = None
        self.findings: list[DetectionFinding] = []
        self.paths: list[AttackPath] = []
        self.investigations: list[InvestigationSummary] = []
        self.user_rankings: list[RankedEntity] = []
        self.host_rankings: list[RankedEntity] = []
        self.stats: Optional[DashboardStats] = None
        self.scenarios: list[ReplayScenario] = []
        self.last_replay: Optional[ReplayResult] = None
        self.ready: bool = False

    def replace_all(
        self,
        *,
        events: list[NormalizedEvent],
        graph: AttackGraph,
        findings: list[DetectionFinding],
        paths: list[AttackPath],
        investigations: list[InvestigationSummary],
        user_rankings: list[RankedEntity],
        host_rankings: list[RankedEntity],
        stats: DashboardStats,
        scenarios: list[ReplayScenario],
    ) -> None:
        with self._lock:
            self.events = events
            self.graph = graph
            self.findings = findings
            self.paths = paths
            self.investigations = investigations
            self.user_rankings = user_rankings
            self.host_rankings = host_rankings
            self.stats = stats
            self.scenarios = scenarios
            self.ready = True


store = InvestigationStore()
