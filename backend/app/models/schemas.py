"""Pydantic schemas for LateralX API and engine."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EventSource(str, Enum):
    WINDOWS_SECURITY = "windows_security"
    SYSMON = "sysmon"
    SYNTHETIC = "synthetic"


class EventCategory(str, Enum):
    LOGON = "logon"
    LOGOFF = "logoff"
    PROCESS = "process"
    NETWORK = "network"
    AUTH = "auth"
    ACCOUNT = "account"
    PRIVILEGE = "privilege"
    POLICY = "policy"
    OTHER = "other"


class EvidenceKind(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NodeType(str, Enum):
    USER = "user"
    HOST = "host"
    PROCESS = "process"
    IP = "ip"


# ─── Telemetry ───────────────────────────────────────────────────────────────


class NormalizedEvent(BaseModel):
    event_id: str
    source: EventSource
    category: EventCategory
    event_code: int
    timestamp: datetime
    host: str
    user: Optional[str] = None
    sid: Optional[str] = None
    src_host: Optional[str] = None
    dst_host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    logon_type: Optional[int] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    target_user: Optional[str] = None
    status: Optional[str] = None
    privilege: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list)


# ─── Graph ───────────────────────────────────────────────────────────────────


class GraphNode(BaseModel):
    id: str
    label: str
    type: NodeType
    privilege: Optional[str] = None
    sid: Optional[str] = None
    status: Optional[str] = None
    risk_score: float = 0.0
    rank: Optional[int] = None
    meta: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    event_codes: list[int] = Field(default_factory=list)
    kind: EvidenceKind = EvidenceKind.OBSERVED
    weight: float = 1.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_ids: list[str] = Field(default_factory=list)
    label: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: dict[str, Any] = Field(default_factory=dict)


# ─── Detection / Investigation ───────────────────────────────────────────────


class DetectionFinding(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float
    title: str
    description: str
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    timestamp: datetime
    kind: EvidenceKind = EvidenceKind.OBSERVED


class AttackPathStep(BaseModel):
    step: int
    timestamp: datetime
    action: str
    host: str
    user: Optional[str] = None
    detail: str
    event_ids: list[str] = Field(default_factory=list)
    kind: EvidenceKind = EvidenceKind.OBSERVED
    confidence: float = 1.0


class AttackPath(BaseModel):
    id: str
    name: str
    severity: Severity
    confidence: float
    start_host: str
    end_host: str
    compromised_hosts: list[str]
    steps: list[AttackPathStep]
    findings: list[str] = Field(default_factory=list)
    summary: str
    recommended_response: list[str] = Field(default_factory=list)
    timeline_start: datetime
    timeline_end: datetime


class InvestigationSummary(BaseModel):
    id: str
    title: str
    narrative: str
    severity: Severity
    confidence: float
    attack_path_id: Optional[str] = None
    key_entities: dict[str, list[str]] = Field(default_factory=dict)
    evidence_links: list[dict[str, str]] = Field(default_factory=list)
    recommended_response: list[str] = Field(default_factory=list)
    created_at: datetime


class RankedEntity(BaseModel):
    rank: int
    id: str
    label: str
    type: NodeType
    score: float
    connections: int
    privilege: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class DashboardStats(BaseModel):
    total_events: int
    total_hosts: int
    total_users: int
    total_findings: int
    critical_findings: int
    attack_paths: int
    observed_edges: int
    inferred_edges: int
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    detection_rate: float
    false_positive_rate: float
    avg_latency_ms: float
    path_accuracy: float


class FilterQuery(BaseModel):
    field: str = "username"
    value: str = ""
    category: Optional[str] = None
    logon_type: Optional[int] = None


class PathSearchRequest(BaseModel):
    source: str
    target: str
    max_hops: int = 6


class PathSearchResult(BaseModel):
    paths: list[list[str]]
    edges_used: list[str]
    confidence: float


class ReplayScenario(BaseModel):
    id: str
    name: str
    description: str
    hosts: list[str]
    expected_techniques: list[str]
    status: str = "ready"


class ReplayResult(BaseModel):
    scenario_id: str
    detected: bool
    findings_matched: list[str]
    path_reconstructed: bool
    detection_rate: float
    false_positives: int
    latency_ms: float
    path_accuracy: float
    summary: str
