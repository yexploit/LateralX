"""Reconstruct multi-host attack paths from correlated telemetry."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.models.schemas import (
    AttackPath,
    AttackPathStep,
    DetectionFinding,
    EvidenceKind,
    InvestigationSummary,
    NormalizedEvent,
    Severity,
)


def reconstruct_paths(
    events: list[NormalizedEvent],
    findings: list[DetectionFinding],
) -> list[AttackPath]:
    """Build an ordered path from lateral / suspicious events across hosts."""
    interesting = [
        e
        for e in events
        if _is_interesting(e)
    ]
    if not interesting:
        # Fall back: use finding-linked events
        finding_ids = {eid for f in findings for eid in f.event_ids}
        interesting = [e for e in events if e.event_id in finding_ids]
    if not interesting:
        return []

    interesting.sort(key=lambda e: e.timestamp)
    steps: list[AttackPathStep] = []
    for i, ev in enumerate(interesting, start=1):
        action, detail, conf, kind = _describe(ev)
        steps.append(
            AttackPathStep(
                step=i,
                timestamp=ev.timestamp,
                action=action,
                host=ev.host,
                user=ev.user,
                detail=detail,
                event_ids=[ev.event_id],
                kind=kind,
                confidence=conf,
            )
        )

    hosts_ordered = _unique([s.host for s in steps])
    start = hosts_ordered[0]
    end = hosts_ordered[-1]
    sev = (
        Severity.CRITICAL
        if any(f.severity == Severity.CRITICAL for f in findings)
        else Severity.HIGH
        if findings
        else Severity.MEDIUM
    )
    conf = max((f.confidence for f in findings), default=0.65)

    summary = (
        f"Reconstructed {len(steps)} evidence steps across {len(hosts_ordered)} host(s) "
        f"from {start} toward {end}. "
        "Edges combine successful remote logons, process execution, and directory activity. "
        "Observed steps are backed by telemetry; inferred relationships are labeled separately in the graph."
    )

    responses = [
        "Isolate hosts on the reconstructed path and preserve volatile evidence.",
        "Reset credentials for accounts seen in remote logons and privilege events.",
        "Hunt for additional Type-3 / Type-10 logons from the same source IPs/hosts.",
        "Review remote service installation and scheduled task persistence on destination hosts.",
        "Validate directory replication / privileged AD changes if DC activity is present.",
    ]

    path = AttackPath(
        id=f"path-{uuid4().hex[:8]}",
        name=f"Movement path: {start} -> {end}" if start != end else f"Activity path on {start}",
        severity=sev,
        confidence=round(conf, 2),
        start_host=start,
        end_host=end,
        compromised_hosts=hosts_ordered,
        steps=steps[:80],
        findings=[f.id for f in findings],
        summary=summary,
        recommended_response=responses,
        timeline_start=steps[0].timestamp,
        timeline_end=steps[-1].timestamp,
    )
    return [path]


def build_investigations(
    paths: list[AttackPath],
    findings: list[DetectionFinding],
) -> list[InvestigationSummary]:
    out: list[InvestigationSummary] = []
    for path in paths:
        related = [f for f in findings if f.id in path.findings] or findings
        evidence = [
            {
                "label": f.title,
                "href": f"#finding-{f.id}",
                "kind": f.kind.value,
                "severity": f.severity.value,
            }
            for f in related
        ]
        for step in path.steps[:8]:
            evidence.append(
                {
                    "label": f"Step {step.step}: {step.action}",
                    "href": f"#event-{step.event_ids[0]}" if step.event_ids else "#timeline",
                    "kind": step.kind.value,
                    "host": step.host,
                }
            )

        narrative = (
            f"Investigation correlates {len(path.steps)} telemetry steps across "
            f"{len(path.compromised_hosts)} hosts. Confidence {int(path.confidence * 100)}%. "
            f"Entry host {path.start_host}; deepest reach {path.end_host}. "
            f"{path.summary}"
        )
        out.append(
            InvestigationSummary(
                id=f"inv-{uuid4().hex[:8]}",
                title=path.name,
                narrative=narrative,
                severity=path.severity,
                confidence=path.confidence,
                attack_path_id=path.id,
                key_entities={
                    "hosts": path.compromised_hosts,
                    "users": sorted({s.user for s in path.steps if s.user}),
                    "techniques": sorted({t for f in related for t in f.mitre_techniques}),
                },
                evidence_links=evidence,
                recommended_response=path.recommended_response,
                created_at=datetime.now(timezone.utc),
            )
        )
    return out


def _is_interesting(ev: NormalizedEvent) -> bool:
    if ev.labels and set(ev.labels).intersection(
        {
            "foothold",
            "encoded_command",
            "credential_access",
            "lateral",
            "rdp",
            "psexec",
            "remote_exec",
            "dcsync",
            "discovery",
            "add_user",
            "ntlm_remote",
            "suspicious",
        }
    ):
        return True
    if ev.event_code in {4624} and ev.logon_type in {3, 10} and (ev.src_host or ev.src_ip):
        return True
    if ev.event_code in {1, 4688} and ev.command_line and any(
        x in ev.command_line.lower() for x in ("-enc", "mimikatz", "psexec", "frombase64")
    ):
        return True
    if ev.event_code in {4662, 4720, 4719}:
        return True
    return False


def _describe(ev: NormalizedEvent) -> tuple[str, str, float, EvidenceKind]:
    labels = set(ev.labels)
    if "encoded_command" in labels or "foothold" in labels:
        return (
            "Suspicious execution",
            f"Encoded/obfuscated command on {ev.host}: {(ev.command_line or ev.process_name or '')[:160]}",
            0.9,
            EvidenceKind.OBSERVED,
        )
    if "credential_access" in labels:
        return (
            "Credential access",
            f"{ev.process_name or 'tool'} — possible credential dumping",
            0.95,
            EvidenceKind.OBSERVED,
        )
    if "rdp" in labels or ev.logon_type == 10:
        return (
            "RDP lateral movement",
            f"Remote interactive logon to {ev.host} from {ev.src_host or ev.src_ip or 'unknown'}",
            0.88,
            EvidenceKind.OBSERVED,
        )
    if "psexec" in labels or "remote_exec" in labels:
        return (
            "Remote execution",
            f"{ev.process_name or 'service'} remote execution pattern",
            0.92,
            EvidenceKind.OBSERVED,
        )
    if "dcsync" in labels or ev.event_code == 4662:
        return (
            "Directory replication / DCSync",
            f"Privileged directory activity on {ev.host}",
            0.93,
            EvidenceKind.OBSERVED,
        )
    if "add_user" in labels or ev.event_code == 4720:
        return (
            "Account change",
            f"Account create/change: {ev.target_user or ev.user or 'unknown'}",
            0.8,
            EvidenceKind.OBSERVED,
        )
    if ev.logon_type == 3 or "ntlm_remote" in labels or "lateral" in labels:
        return (
            "Network logon",
            f"Type-{ev.logon_type or 3} logon on {ev.host} as {ev.user or 'unknown'} "
            f"from {ev.src_host or ev.src_ip or 'n/a'}",
            0.84,
            EvidenceKind.OBSERVED,
        )
    return (
        ev.category.value.replace("_", " ").title(),
        f"Event {ev.event_code} on {ev.host}",
        0.7,
        EvidenceKind.OBSERVED,
    )


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        key = x.lower()
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out
