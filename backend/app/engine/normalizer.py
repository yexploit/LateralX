"""Normalize heterogeneous telemetry into a shared event model."""

from __future__ import annotations

from typing import Any

from app.models.schemas import EventCategory, EventSource, NormalizedEvent


LOGON_TYPE_LABELS = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


def logon_type_name(code: int | None) -> str:
    if code is None:
        return "Unknown"
    return LOGON_TYPE_LABELS.get(code, f"Type{code}")


def normalize_raw_event(raw: dict[str, Any]) -> NormalizedEvent:
    """Accept already-normalized or loosely structured dicts."""
    if "event_id" in raw and "event_code" in raw:
        return NormalizedEvent.model_validate(raw)

    source = EventSource(raw.get("source", "synthetic"))
    code = int(raw.get("EventID") or raw.get("event_code") or 0)
    category = _infer_category(code, raw)
    return NormalizedEvent(
        event_id=str(raw.get("event_id") or raw.get("RecordId") or f"raw-{hash(str(raw)) & 0xFFFFFFFF:x}"),
        source=source,
        category=category,
        event_code=code,
        timestamp=raw["timestamp"] if "timestamp" in raw else raw["TimeCreated"],
        host=str(raw.get("host") or raw.get("Computer") or "unknown"),
        user=raw.get("user") or raw.get("TargetUserName"),
        sid=raw.get("sid") or raw.get("TargetUserSid"),
        src_host=raw.get("src_host") or raw.get("WorkstationName"),
        dst_host=raw.get("dst_host"),
        src_ip=raw.get("src_ip") or raw.get("IpAddress"),
        dst_ip=raw.get("dst_ip"),
        logon_type=_maybe_int(raw.get("logon_type") or raw.get("LogonType")),
        process_name=raw.get("process_name") or raw.get("Image"),
        process_id=_maybe_int(raw.get("process_id") or raw.get("ProcessId")),
        parent_process=raw.get("parent_process") or raw.get("ParentImage"),
        parent_pid=_maybe_int(raw.get("parent_pid") or raw.get("ParentProcessId")),
        command_line=raw.get("command_line") or raw.get("CommandLine"),
        target_user=raw.get("target_user"),
        status=raw.get("status"),
        privilege=raw.get("privilege"),
        raw=raw,
        labels=list(raw.get("labels") or []),
    )


def _infer_category(code: int, raw: dict[str, Any]) -> EventCategory:
    if code in {4624, 4625, 4634, 4648}:
        return EventCategory.LOGON
    if code in {4672}:
        return EventCategory.PRIVILEGE
    if code in {4720, 4726, 4732, 4662}:
        return EventCategory.ACCOUNT
    if code in {4719}:
        return EventCategory.POLICY
    if code in {4776, 4768, 4769}:
        return EventCategory.AUTH
    if code == 1:
        return EventCategory.PROCESS
    if code == 3:
        return EventCategory.NETWORK
    cat = raw.get("category")
    if cat:
        return EventCategory(cat)
    return EventCategory.OTHER


def _maybe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def filter_events(
    events: list[NormalizedEvent],
    *,
    field: str | None = None,
    value: str | None = None,
    category: str | None = None,
    logon_type: int | None = None,
    labels: list[str] | None = None,
) -> list[NormalizedEvent]:
    out = events
    if category:
        out = [e for e in out if e.category.value == category or category in e.labels]
    if logon_type is not None:
        out = [e for e in out if e.logon_type == logon_type]
    if labels:
        label_set = set(labels)
        out = [e for e in out if label_set.intersection(e.labels)]
    if field and value:
        q = value.lower().strip()
        if not q:
            return out

        def match(e: NormalizedEvent) -> bool:
            if field in {"username", "user"}:
                return bool(e.user and q in e.user.lower())
            if field == "host":
                hosts = [e.host, e.src_host, e.dst_host]
                return any(h and q in h.lower() for h in hosts)
            if field == "ip":
                ips = [e.src_ip, e.dst_ip]
                return any(ip and q in ip.lower() for ip in ips)
            if field == "process":
                return bool(
                    (e.process_name and q in e.process_name.lower())
                    or (e.command_line and q in e.command_line.lower())
                )
            if field == "event_code":
                return str(e.event_code) == q
            blob = " ".join(
                str(x)
                for x in [e.user, e.host, e.src_host, e.dst_host, e.process_name, *e.labels]
                if x
            ).lower()
            return q in blob

        out = [e for e in out if match(e)]
    return out
