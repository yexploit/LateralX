"""Parse Windows EVTX, Sysmon/Security XML, JSON/JSONL, and CSV into normalized events."""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from app.models.schemas import EventCategory, EventSource, NormalizedEvent
from app.engine.normalizer import normalize_raw_event

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
)


def parse_file(path: Path) -> list[NormalizedEvent]:
    suffix = path.suffix.lower()
    data = path.read_bytes()
    return parse_bytes(data, filename=path.name, suffix=suffix)


def parse_bytes(data: bytes, filename: str = "upload", suffix: str | None = None) -> list[NormalizedEvent]:
    name = filename.lower()
    suffix = (suffix or Path(filename).suffix).lower()

    if suffix == ".evtx" or name.endswith(".evtx"):
        return _parse_evtx(data, filename)
    if suffix in {".xml"} or b"<Event" in data[:2000] or b"<Events" in data[:500]:
        return _parse_xml(data, filename)
    if suffix in {".jsonl", ".ndjson"}:
        return _parse_jsonl(data, filename)
    if suffix == ".json":
        return _parse_json(data, filename)
    if suffix == ".csv":
        return _parse_csv(data, filename)
    # sniff
    text = data[:400].lstrip()
    if text.startswith(b"{") or text.startswith(b"["):
        return _parse_json(data, filename)
    if b"," in text and b"\n" in text:
        return _parse_csv(data, filename)
    raise ValueError(f"Unsupported file type for {filename}. Use .evtx .xml .json .jsonl .csv")


def _eid(prefix: str = "evt") -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None:
        return datetime.now(timezone.utc)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Windows FILETIME-ish or epoch
    try:
        epoch = float(s)
        if epoch > 1e12:
            epoch /= 1000.0
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except Exception as exc:
        raise ValueError(f"Unparseable timestamp: {value}") from exc


def _parse_json(data: bytes, filename: str) -> list[NormalizedEvent]:
    obj = json.loads(data.decode("utf-8-sig"))
    if isinstance(obj, dict) and "events" in obj:
        obj = obj["events"]
    if isinstance(obj, dict):
        obj = [obj]
    if not isinstance(obj, list):
        raise ValueError("JSON must be an object, array, or {events:[...]}")
    out: list[NormalizedEvent] = []
    for item in obj:
        if not isinstance(item, dict):
            continue
        out.append(_from_loose_dict(item, filename))
    return out


def _parse_jsonl(data: bytes, filename: str) -> list[NormalizedEvent]:
    out: list[NormalizedEvent] = []
    for line in data.decode("utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        if isinstance(item, dict):
            out.append(_from_loose_dict(item, filename))
    return out


def _parse_csv(data: bytes, filename: str) -> list[NormalizedEvent]:
    text = data.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    return [_from_loose_dict(dict(row), filename) for row in reader]


def _from_loose_dict(raw: dict[str, Any], filename: str) -> NormalizedEvent:
    # Already normalized?
    if "event_code" in raw and "timestamp" in raw and "host" in raw:
        if "event_id" not in raw:
            raw = {**raw, "event_id": _eid()}
        try:
            return NormalizedEvent.model_validate(raw)
        except Exception:
            pass

    # PowerShell Get-WinEvent style
    code = _first_int(
        raw,
        "event_code",
        "EventID",
        "Id",
        "Event Id",
        "eventid",
    )
    ts = raw.get("timestamp") or raw.get("TimeCreated") or raw.get("time") or raw.get("@timestamp")
    host = (
        raw.get("host")
        or raw.get("Computer")
        or raw.get("MachineName")
        or raw.get("computer")
        or "unknown"
    )
    # nested EventData
    ed = raw.get("EventData") or raw.get("event_data") or {}
    if isinstance(ed, list):
        ed = {str(i.get("Name") or i.get("name")): i.get("Value") or i.get("#text") or i.get("value") for i in ed if isinstance(i, dict)}
    if not isinstance(ed, dict):
        ed = {}

    user = (
        raw.get("user")
        or raw.get("TargetUserName")
        or ed.get("TargetUserName")
        or ed.get("User")
        or raw.get("SubjectUserName")
    )
    domain = raw.get("TargetDomainName") or ed.get("TargetDomainName")
    if user and domain and "\\" not in str(user):
        user = f"{domain}\\{user}"

    src_ip = raw.get("src_ip") or raw.get("IpAddress") or ed.get("IpAddress") or ed.get("SourceIp")
    src_host = (
        raw.get("src_host")
        or raw.get("WorkstationName")
        or ed.get("WorkstationName")
        or ed.get("SourceHostname")
    )
    image = raw.get("process_name") or raw.get("Image") or ed.get("Image") or ed.get("NewProcessName")
    if image and "\\" in str(image):
        process_name = str(image).split("\\")[-1]
    else:
        process_name = image

    parent = raw.get("parent_process") or raw.get("ParentImage") or ed.get("ParentImage")
    if parent and "\\" in str(parent):
        parent_name = str(parent).split("\\")[-1]
    else:
        parent_name = parent

    source = EventSource.WINDOWS_SECURITY
    channel = str(raw.get("Channel") or raw.get("LogName") or "").lower()
    if "sysmon" in channel or code in {1, 3, 10, 11} and (image or ed.get("Image")):
        source = EventSource.SYSMON
    if raw.get("source") in {s.value for s in EventSource}:
        source = EventSource(raw["source"])

    payload = {
        "event_id": str(raw.get("event_id") or raw.get("RecordId") or _eid()),
        "source": source.value,
        "category": "other",
        "event_code": code or 0,
        "timestamp": _parse_ts(ts),
        "host": str(host).rstrip("$"),
        "user": user,
        "sid": raw.get("sid") or raw.get("TargetUserSid") or ed.get("TargetUserSid"),
        "src_host": src_host,
        "dst_host": raw.get("dst_host") or ed.get("DestinationHostname"),
        "src_ip": src_ip,
        "dst_ip": raw.get("dst_ip") or ed.get("DestinationIp"),
        "logon_type": _first_int(raw, "logon_type", "LogonType") or _first_int(ed, "LogonType"),
        "process_name": process_name,
        "process_id": _first_int(raw, "process_id", "ProcessId") or _first_int(ed, "ProcessId"),
        "parent_process": parent_name,
        "parent_pid": _first_int(raw, "parent_pid", "ParentProcessId") or _first_int(ed, "ParentProcessId"),
        "command_line": raw.get("command_line") or raw.get("CommandLine") or ed.get("CommandLine"),
        "target_user": raw.get("target_user") or ed.get("TargetUserName"),
        "status": raw.get("status") or ed.get("Status"),
        "privilege": raw.get("privilege"),
        "raw": {**raw, "EventData": ed, "_source_file": filename},
        "labels": list(raw.get("labels") or []),
    }
    # category inference via normalizer helpers
    ev = normalize_raw_event(payload)
    return ev


def _first_int(obj: dict[str, Any], *keys: str) -> int | None:
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            try:
                return int(str(obj[k]).strip())
            except ValueError:
                continue
    return None


def _parse_xml(data: bytes, filename: str) -> list[NormalizedEvent]:
    text = data.decode("utf-8-sig", errors="replace")
    # Strip namespaces for easier parsing
    text = re.sub(r'\sxmlns="[^"]+"', "", text)
    text = re.sub(r"</?(\w+:)", lambda m: m.group(0).replace(m.group(1), ""), text)
    root = ET.fromstring(text)
    events_xml = []
    if root.tag.endswith("Event"):
        events_xml = [root]
    else:
        events_xml = list(root.findall(".//Event"))
        if not events_xml and root.tag.endswith("Events"):
            events_xml = list(root)
    out: list[NormalizedEvent] = []
    for node in events_xml:
        out.append(_event_xml_to_normalized(node, filename))
    return out


def _event_xml_to_normalized(node: ET.Element, filename: str) -> NormalizedEvent:
    system = node.find("System") or node
    event_id = 0
    eid_node = system.find("EventID")
    if eid_node is not None and eid_node.text:
        event_id = int(re.sub(r"\D", "", eid_node.text) or 0)
    ts_node = system.find("TimeCreated")
    ts = None
    if ts_node is not None:
        ts = ts_node.attrib.get("SystemTime") or ts_node.text
    computer = (system.findtext("Computer") or "unknown").rstrip("$")
    channel = system.findtext("Channel") or ""
    record_id = system.findtext("EventRecordID") or _eid()

    data_map: dict[str, str] = {}
    event_data = node.find("EventData")
    if event_data is not None:
        for d in event_data.findall("Data"):
            name = d.attrib.get("Name") or d.attrib.get("name")
            if name:
                data_map[name] = (d.text or "").strip()

    raw = {
        "event_id": f"xml-{record_id}",
        "EventID": event_id,
        "TimeCreated": ts,
        "Computer": computer,
        "Channel": channel,
        "EventData": data_map,
        "source": "sysmon" if "sysmon" in channel.lower() else "windows_security",
    }
    return _from_loose_dict(raw, filename)


def _parse_evtx(data: bytes, filename: str) -> list[NormalizedEvent]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise RuntimeError(
            "EVTX support requires python-evtx. Install: pip install python-evtx"
        ) from exc

    # python-evtx expects a path; write temp file
    import tempfile

    out: list[NormalizedEvent] = []
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        with Evtx(tmp_path) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    evs = _parse_xml(xml.encode("utf-8"), filename)
                    out.extend(evs)
                except Exception:
                    continue
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return out
