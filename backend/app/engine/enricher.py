"""Enrich normalized events with investigation labels from real telemetry content."""

from __future__ import annotations

import re

from app.models.schemas import NormalizedEvent

_ENC_PS = re.compile(r"(-enc|-encodedcommand|frombase64string)", re.I)
_MIMIKATZ = re.compile(r"(mimikatz|sekurlsa|lsadump|procdump|secretsdump|nanodump)", re.I)
_PSEXEC = re.compile(r"(psexesvc|psexec|paexec|remcom)", re.I)
_RDP_CLIENT = re.compile(r"(mstsc\.exe|rdpclip)", re.I)
_DCSYNC = re.compile(
    r"(replicating directory changes|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|"
    r"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|dcsync)",
    re.I,
)


def enrich_event(ev: NormalizedEvent) -> NormalizedEvent:
    labels = set(ev.labels)
    cmd = " ".join(
        x
        for x in [
            ev.command_line,
            ev.process_name,
            ev.parent_process,
            str(ev.raw),
        ]
        if x
    )

    if ev.event_code == 4624:
        if ev.logon_type == 3:
            labels.update({"network_logon", "ntlm_remote"})
            if ev.src_host or ev.src_ip:
                labels.add("lateral")
        elif ev.logon_type == 10:
            labels.update({"rdp", "remote_interactive", "lateral"})
        elif ev.logon_type == 4:
            labels.add("batch_logon")
        elif ev.logon_type == 5:
            labels.add("service_logon")
        if ev.status and "fail" in ev.status.lower():
            labels.add("logon_failure")
        else:
            labels.add("logon_success")

    if ev.event_code == 4625:
        labels.add("logon_failure")

    if ev.event_code == 4672:
        labels.update({"special_privileges", "elevated"})
        if not ev.privilege:
            ev.privilege = "SYSTEM"

    if ev.event_code in {4720, 4722, 4726, 4732}:
        labels.add("add_user" if ev.event_code in {4720, 4722, 4732} else "delete_user")

    if ev.event_code == 4719:
        labels.add("audit_policy_change")

    if ev.event_code == 4662 or _DCSYNC.search(cmd):
        labels.update({"dcsync", "directory_replication", "T1003.006"})

    if ev.event_code in {1, 4688} or ev.category.value == "process":
        if _ENC_PS.search(cmd):
            labels.update({"encoded_command", "foothold", "suspicious"})
        if _MIMIKATZ.search(cmd):
            labels.update({"credential_access", "lsass", "T1003"})
        if _PSEXEC.search(cmd):
            labels.update({"psexec", "remote_exec", "T1021.002", "lateral"})
        if re.search(r"powershell", cmd, re.I) and re.search(r"hidden|bypass|noprofile", cmd, re.I):
            labels.add("suspicious")

    if ev.event_code == 3 or ev.category.value == "network":
        if _RDP_CLIENT.search(cmd) or (ev.raw and str(ev.raw.get("destination_port") or ev.raw.get("DestinationPort") or "") == "3389"):
            labels.update({"rdp_client", "rdp", "lateral"})
        port = str(ev.raw.get("destination_port") or ev.raw.get("DestinationPort") or "")
        if port in {"389", "636", "3268", "3269"}:
            labels.add("ldap")

    # Cross-host signal
    if ev.src_host and ev.host and ev.src_host.lower().split(".")[0] != ev.host.lower().split(".")[0]:
        if ev.event_code in {4624, 4648, 3} or "lateral" in labels:
            labels.add("lateral")

    if ev.privilege and ev.privilege.upper() in {"SYSTEM", "ADMINISTRATOR", "HIGH"}:
        labels.add("elevated")

    ev.labels = sorted(labels)
    return ev


def enrich_events(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    return [enrich_event(ev) for ev in events]
