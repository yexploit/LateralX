"""Generate a realistic 3-host lateral movement scenario for demos."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from app.models.schemas import EventCategory, EventSource, NormalizedEvent

UTC = timezone.utc


def _eid() -> str:
    return f"evt-{uuid4().hex[:12]}"


def _ts(base: datetime, minutes: float) -> datetime:
    return base + timedelta(minutes=minutes)


def generate_scenario_events(base: datetime | None = None) -> list[NormalizedEvent]:
    """
    Controlled intrusion across three hosts:

      workstation-01  →  fileserver-01  →  dc-01

    Stages:
      1. Initial foothold / suspicious process on workstation
      2. Credential access & network logon to fileserver (admin)
      3. RDP lateral movement
      4. Remote process creation / PsExec-style activity
      5. DCSync / directory replication attempt against DC
      6. Benign background noise for FP realism
    """
    base = base or datetime(2026, 3, 12, 9, 15, 0, tzinfo=UTC)
    events: list[NormalizedEvent] = []

    domain = "CORP"
    admin = "administrator"
    admin_sid = "S-1-5-21-1524084746-3249201829-3114449661-500"
    svc = "svc_backup"
    svc_sid = "S-1-5-21-1524084746-3249201829-3114449661-1108"
    alice = "alice.chen"
    alice_sid = "S-1-5-21-1524084746-3249201829-3114449661-1450"
    bob = "bob.martinez"
    bob_sid = "S-1-5-21-1524084746-3249201829-3114449661-1451"

    ws = "workstation-01"
    fs = "fileserver-01"
    dc = "dc-01"
    ws_ip = "10.10.20.41"
    fs_ip = "10.10.20.15"
    dc_ip = "10.10.20.10"

    def add(**kwargs: Any) -> None:
        events.append(NormalizedEvent(**kwargs))

    # ── Benign morning activity ──────────────────────────────────────────────
    for i, (user, sid, host) in enumerate(
        [
            (alice, alice_sid, ws),
            (bob, bob_sid, "workstation-02"),
            (svc, svc_sid, fs),
        ]
    ):
        add(
            event_id=_eid(),
            source=EventSource.WINDOWS_SECURITY,
            category=EventCategory.LOGON,
            event_code=4624,
            timestamp=_ts(base, -40 + i * 3),
            host=host,
            user=f"{domain}\\{user}",
            sid=sid,
            logon_type=2,
            privilege="User",
            status="success",
            labels=["benign", "interactive"],
        )

    # ── Stage 1: foothold on workstation-01 ──────────────────────────────────
    add(
        event_id=_eid(),
        source=EventSource.SYSMON,
        category=EventCategory.PROCESS,
        event_code=1,
        timestamp=_ts(base, 0),
        host=ws,
        user=f"{domain}\\{alice}",
        sid=alice_sid,
        process_name="powershell.exe",
        process_id=4820,
        parent_process="explorer.exe",
        parent_pid=3104,
        command_line=(
            "powershell.exe -NoP -W Hidden -Enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        ),
        labels=["suspicious", "encoded_command", "foothold"],
        raw={"image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    )
    add(
        event_id=_eid(),
        source=EventSource.SYSMON,
        category=EventCategory.PROCESS,
        event_code=1,
        timestamp=_ts(base, 1.5),
        host=ws,
        user=f"{domain}\\{alice}",
        sid=alice_sid,
        process_name="mimikatz.exe",
        process_id=5102,
        parent_process="powershell.exe",
        parent_pid=4820,
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        labels=["credential_access", "lsass", "T1003"],
        raw={"hashes": "MD5=A1B2C3D4"},
    )
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.PRIVILEGE,
        event_code=4672,
        timestamp=_ts(base, 2),
        host=ws,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        privilege="SYSTEM",
        status="assigned",
        labels=["special_privileges", "elevated"],
    )

    # ── Stage 2: network logon to fileserver as administrator ────────────────
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.LOGON,
        event_code=4624,
        timestamp=_ts(base, 8),
        host=fs,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=ws,
        src_ip=ws_ip,
        dst_host=fs,
        dst_ip=fs_ip,
        logon_type=3,
        privilege="SYSTEM",
        status="success",
        labels=["ntlm_remote", "lateral", "network_logon"],
    )
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.AUTH,
        event_code=4776,
        timestamp=_ts(base, 8.1),
        host=dc,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=ws,
        src_ip=ws_ip,
        status="success",
        labels=["ntlm_auth", "credential_reuse"],
    )

    # Failed noise then success (bruteforce-ish decoy)
    for i in range(2):
        add(
            event_id=_eid(),
            source=EventSource.WINDOWS_SECURITY,
            category=EventCategory.LOGON,
            event_code=4625,
            timestamp=_ts(base, 6 + i * 0.4),
            host=fs,
            user=f"{domain}\\guest",
            src_host=ws,
            src_ip=ws_ip,
            dst_host=fs,
            logon_type=3,
            status="failure",
            labels=["logon_failure"],
        )

    # ── Stage 3: RDP to fileserver ───────────────────────────────────────────
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.LOGON,
        event_code=4624,
        timestamp=_ts(base, 14),
        host=fs,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=ws,
        src_ip=ws_ip,
        dst_host=fs,
        dst_ip=fs_ip,
        logon_type=10,
        privilege="SYSTEM",
        status="success",
        labels=["rdp", "lateral", "remote_interactive"],
    )
    add(
        event_id=_eid(),
        source=EventSource.SYSMON,
        category=EventCategory.NETWORK,
        event_code=3,
        timestamp=_ts(base, 14.2),
        host=ws,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=ws,
        src_ip=ws_ip,
        dst_host=fs,
        dst_ip=fs_ip,
        process_name="mstsc.exe",
        process_id=6201,
        labels=["rdp_client", "lateral"],
        raw={"destination_port": 3389},
    )

    # ── Stage 4: remote service / process on fileserver ──────────────────────
    add(
        event_id=_eid(),
        source=EventSource.SYSMON,
        category=EventCategory.PROCESS,
        event_code=1,
        timestamp=_ts(base, 18),
        host=fs,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        process_name="PSEXESVC.exe",
        process_id=1888,
        parent_process="services.exe",
        parent_pid=668,
        command_line="C:\\Windows\\PSEXESVC.exe",
        labels=["psexec", "remote_exec", "T1021.002"],
    )
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.LOGON,
        event_code=4624,
        timestamp=_ts(base, 18.1),
        host=fs,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=ws,
        src_ip=ws_ip,
        logon_type=3,
        privilege="SYSTEM",
        status="success",
        labels=["service_logon_context", "lateral"],
    )
    add(
        event_id=_eid(),
        source=EventSource.SYSMON,
        category=EventCategory.PROCESS,
        event_code=1,
        timestamp=_ts(base, 18.5),
        host=fs,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        process_name="cmd.exe",
        process_id=4022,
        parent_process="PSEXESVC.exe",
        parent_pid=1888,
        command_line='cmd.exe /c whoami & net group "Domain Admins" /domain',
        labels=["discovery", "T1087"],
    )

    # ── Stage 5: move toward DC — network + DCSync indicators ────────────────
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.LOGON,
        event_code=4624,
        timestamp=_ts(base, 26),
        host=dc,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=fs,
        src_ip=fs_ip,
        dst_host=dc,
        dst_ip=dc_ip,
        logon_type=3,
        privilege="SYSTEM",
        status="success",
        labels=["ntlm_remote", "domain_controller", "lateral"],
    )
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.ACCOUNT,
        event_code=4662,
        timestamp=_ts(base, 27),
        host=dc,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=fs,
        src_ip=fs_ip,
        privilege="SYSTEM",
        status="success",
        labels=["dcsync", "directory_replication", "T1003.006"],
        raw={
            "object_server": "DS",
            "access_mask": "0x100",
            "properties": ["Replicating Directory Changes All"],
        },
    )
    add(
        event_id=_eid(),
        source=EventSource.SYSMON,
        category=EventCategory.NETWORK,
        event_code=3,
        timestamp=_ts(base, 27.1),
        host=fs,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_ip=fs_ip,
        dst_ip=dc_ip,
        dst_host=dc,
        process_name="lsass.exe",
        process_id=712,
        labels=["ldap", "dcsync_traffic"],
        raw={"destination_port": 389},
    )

    # ── Extra domain activity / rankings richness ────────────────────────────
    for i, host in enumerate(["workstation-02", "workstation-03", "fileserver-02"]):
        add(
            event_id=_eid(),
            source=EventSource.WINDOWS_SECURITY,
            category=EventCategory.LOGON,
            event_code=4624,
            timestamp=_ts(base, 5 + i * 7),
            host=host,
            user=f"{domain}\\{svc}",
            sid=svc_sid,
            src_host=fs,
            src_ip=fs_ip,
            logon_type=5,
            privilege="Service",
            status="success",
            labels=["service_logon", "benign"],
        )

    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.ACCOUNT,
        event_code=4720,
        timestamp=_ts(base, 30),
        host=dc,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        target_user=f"{domain}\\tmp_recon",
        privilege="SYSTEM",
        status="created",
        labels=["add_user", "persistence"],
    )
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.POLICY,
        event_code=4719,
        timestamp=_ts(base, 31),
        host=dc,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        privilege="SYSTEM",
        status="changed",
        labels=["audit_policy_change"],
    )

    # Batch / scheduled task style logon
    add(
        event_id=_eid(),
        source=EventSource.WINDOWS_SECURITY,
        category=EventCategory.LOGON,
        event_code=4624,
        timestamp=_ts(base, 22),
        host=fs,
        user=f"{domain}\\{admin}",
        sid=admin_sid,
        src_host=ws,
        logon_type=4,
        privilege="SYSTEM",
        status="success",
        labels=["batch_logon"],
    )

    events.sort(key=lambda e: e.timestamp)
    return events
