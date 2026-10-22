"""Rule-based detection over real Windows / Sysmon telemetry."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from uuid import uuid4

from app.models.schemas import (
    DetectionFinding,
    EvidenceKind,
    NormalizedEvent,
    Severity,
)


def _fid() -> str:
    return f"find-{uuid4().hex[:10]}"


def run_detections(events: list[NormalizedEvent]) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []

    def add(**kwargs) -> None:
        findings.append(DetectionFinding(id=_fid(), **kwargs))

    # Encoded PowerShell
    enc = [
        e
        for e in events
        if "encoded_command" in e.labels
        or (
            e.command_line
            and re.search(r"(-enc|-encodedcommand|frombase64string)", e.command_line, re.I)
        )
    ]
    if enc:
        e0 = enc[0]
        add(
            rule_id="LX-PROC-001",
            rule_name="Suspicious Encoded PowerShell",
            severity=Severity.HIGH,
            confidence=0.9,
            title=f"Encoded PowerShell execution on {e0.host}",
            description=(
                "Process creation shows powershell.exe with encoded/obfuscated arguments, "
                "commonly used to hide download cradles or scripts."
            ),
            hosts=sorted({e.host for e in enc}),
            users=sorted({e.user for e in enc if e.user}),
            event_ids=[e.event_id for e in enc[:40]],
            mitre_techniques=["T1059.001"],
            timestamp=e0.timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # Credential dumping tools
    cred = [
        e
        for e in events
        if "credential_access" in e.labels
        or (
            e.command_line
            and re.search(r"(mimikatz|sekurlsa|procdump|secretsdump|nanodump|lsass)", e.command_line, re.I)
        )
        or (e.process_name and re.search(r"(mimikatz|procdump|nanodump)", e.process_name, re.I))
    ]
    if cred:
        e0 = cred[0]
        add(
            rule_id="LX-CRED-002",
            rule_name="Credential Dumping Activity",
            severity=Severity.CRITICAL,
            confidence=0.95,
            title=f"Credential access tooling on {e0.host}",
            description=(
                "Telemetry matches known credential dumping utilities or LSASS access patterns."
            ),
            hosts=sorted({e.host for e in cred}),
            users=sorted({e.user for e in cred if e.user}),
            event_ids=[e.event_id for e in cred[:40]],
            mitre_techniques=["T1003.001"],
            timestamp=e0.timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # Network / NTLM lateral logons
    ntlm = [
        e
        for e in events
        if e.event_code == 4624
        and e.logon_type == 3
        and (e.src_host or e.src_ip)
        and e.user
        and not _is_machine_account(e.user)
    ]
    if len(ntlm) >= 1:
        hosts = sorted({e.host for e in ntlm})
        if len(hosts) >= 1:
            add(
                rule_id="LX-LAT-010",
                rule_name="NTLM / Network Logon Lateral Pattern",
                severity=Severity.HIGH if len(hosts) > 1 else Severity.MEDIUM,
                confidence=0.82,
                title="Privileged or remote network logons across hosts",
                description=(
                    f"Observed {len(ntlm)} successful Type-3 logons with source host/IP. "
                    "Review for credential reuse and unexpected admin sessions."
                ),
                hosts=hosts,
                users=sorted({e.user for e in ntlm if e.user})[:20],
                event_ids=[e.event_id for e in ntlm[:50]],
                mitre_techniques=["T1021.002", "T1078"],
                timestamp=ntlm[0].timestamp,
                kind=EvidenceKind.OBSERVED,
            )

    # RDP
    rdp = [
        e
        for e in events
        if e.logon_type == 10
        or "rdp" in e.labels
        or (e.process_name and e.process_name.lower() == "mstsc.exe")
    ]
    if rdp:
        add(
            rule_id="LX-LAT-011",
            rule_name="RDP Lateral Movement",
            severity=Severity.HIGH,
            confidence=0.88,
            title="Remote Interactive (RDP) activity detected",
            description=(
                "Logon Type 10 and/or RDP client network activity indicates remote interactive access."
            ),
            hosts=sorted({e.host for e in rdp}),
            users=sorted({e.user for e in rdp if e.user}),
            event_ids=[e.event_id for e in rdp[:40]],
            mitre_techniques=["T1021.001"],
            timestamp=rdp[0].timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # PsExec / remote service
    psexec = [
        e
        for e in events
        if "psexec" in e.labels
        or "remote_exec" in e.labels
        or (
            e.process_name
            and re.search(r"(psexesvc|psexec|paexec)", e.process_name, re.I)
        )
        or (e.command_line and re.search(r"(psexesvc|psexec)", e.command_line, re.I))
    ]
    if psexec:
        add(
            rule_id="LX-EXEC-020",
            rule_name="Remote Service Execution (PsExec-style)",
            severity=Severity.CRITICAL,
            confidence=0.92,
            title="PsExec-style remote execution observed",
            description="Process telemetry matches remote service installation / PsExec patterns.",
            hosts=sorted({e.host for e in psexec}),
            users=sorted({e.user for e in psexec if e.user}),
            event_ids=[e.event_id for e in psexec[:40]],
            mitre_techniques=["T1021.002", "T1569.002"],
            timestamp=psexec[0].timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # DCSync
    dcsync = [
        e
        for e in events
        if "dcsync" in e.labels
        or e.event_code == 4662
        and e.raw
        and re.search(
            r"(replicating directory changes|1131f6ad-9c07-11d1-f79f|1131f6aa-9c07-11d1-f79f)",
            str(e.raw),
            re.I,
        )
    ]
    if dcsync:
        add(
            rule_id="LX-AD-030",
            rule_name="DCSync / Directory Replication",
            severity=Severity.CRITICAL,
            confidence=0.94,
            title="Directory replication rights activity",
            description=(
                "Events indicate use of directory replication permissions consistent with DCSync."
            ),
            hosts=sorted({e.host for e in dcsync}),
            users=sorted({e.user for e in dcsync if e.user}),
            event_ids=[e.event_id for e in dcsync[:40]],
            mitre_techniques=["T1003.006"],
            timestamp=dcsync[0].timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # Account create
    add_user = [e for e in events if e.event_code in {4720, 4722} or "add_user" in e.labels]
    if add_user:
        e0 = add_user[0]
        add(
            rule_id="LX-PERS-040",
            rule_name="Account Creation",
            severity=Severity.MEDIUM,
            confidence=0.8,
            title=f"Account creation on {e0.host}",
            description="Security log shows new account creation — validate change control.",
            hosts=sorted({e.host for e in add_user}),
            users=sorted({e.user for e in add_user if e.user}),
            event_ids=[e.event_id for e in add_user[:20]],
            mitre_techniques=["T1136.001"],
            timestamp=e0.timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # Audit policy
    policy = [e for e in events if e.event_code == 4719 or "audit_policy_change" in e.labels]
    if policy:
        e0 = policy[0]
        add(
            rule_id="LX-DEF-050",
            rule_name="Audit Policy Change",
            severity=Severity.MEDIUM,
            confidence=0.78,
            title=f"Audit policy modified on {e0.host}",
            description="Event 4719 indicates audit policy change that may impair detection coverage.",
            hosts=[e0.host],
            users=[e0.user] if e0.user else [],
            event_ids=[e0.event_id],
            mitre_techniques=["T1562.002"],
            timestamp=e0.timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # Logon failures burst
    fails = [e for e in events if e.event_code == 4625 or "logon_failure" in e.labels]
    if len(fails) >= 5:
        add(
            rule_id="LX-AUTH-060",
            rule_name="Logon Failure Burst",
            severity=Severity.MEDIUM,
            confidence=0.75,
            title=f"Elevated logon failures ({len(fails)} events)",
            description="Multiple failed logons may indicate password spray or brute force.",
            hosts=sorted({e.host for e in fails}),
            users=sorted({e.user for e in fails if e.user})[:20],
            event_ids=[e.event_id for e in fails[:50]],
            mitre_techniques=["T1110"],
            timestamp=fails[0].timestamp,
            kind=EvidenceKind.OBSERVED,
        )

    # Multi-host campaign (inferred)
    lateral_hosts = {
        e.host
        for e in events
        if "lateral" in e.labels or e.logon_type in {3, 10}
    }
    if len(lateral_hosts) >= 2 and len(findings) >= 2:
        add(
            rule_id="LX-CAMP-100",
            rule_name="Multi-Host Lateral Campaign",
            severity=Severity.CRITICAL,
            confidence=0.9,
            title="Correlated multi-host lateral movement campaign",
            description=(
                "Multiple detection signals and cross-host authentication patterns correlate "
                "into a single campaign narrative."
            ),
            hosts=sorted(lateral_hosts),
            users=sorted({u for f in findings for u in f.users})[:20],
            event_ids=[eid for f in findings for eid in f.event_ids][:40],
            mitre_techniques=["T1021", "T1078"],
            timestamp=datetime.now(timezone.utc),
            kind=EvidenceKind.INFERRED,
        )

    findings.sort(key=lambda f: (_sev_rank(f.severity), -f.confidence))
    return findings


def _is_machine_account(user: str) -> bool:
    name = user.split("\\")[-1]
    return name.endswith("$")


def _sev_rank(s: Severity) -> int:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return order[s]
