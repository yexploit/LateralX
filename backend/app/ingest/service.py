"""Ingest orchestration: parse → enrich → persist → analyze."""

from __future__ import annotations

from pathlib import Path

from app.db import clear_events, load_events, save_events
from app.engine.enricher import enrich_events
from app.engine.pipeline import run_pipeline
from app.ingest.parsers import parse_bytes, parse_file
from app.models.schemas import NormalizedEvent
from app.store import store


def ingest_path(path: str | Path, *, reanalyze: bool = True, replace: bool = False) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    if p.is_dir():
        files = sorted(
            [
                *p.rglob("*.evtx"),
                *p.rglob("*.xml"),
                *p.rglob("*.json"),
                *p.rglob("*.jsonl"),
                *p.rglob("*.ndjson"),
                *p.rglob("*.csv"),
            ]
        )
        return ingest_paths(files, reanalyze=reanalyze, replace=replace)
    events = enrich_events(parse_file(p))
    return _commit(events, source=str(p), reanalyze=reanalyze, replace=replace)


def ingest_paths(paths: list[Path], *, reanalyze: bool = True, replace: bool = False) -> dict:
    all_events: list[NormalizedEvent] = []
    sources: list[str] = []
    if replace:
        clear_events()
    for p in paths:
        if not p.is_file():
            continue
        batch = enrich_events(parse_file(p))
        save_events(batch, source_file=str(p))
        all_events.extend(batch)
        sources.append(str(p))
    events = load_events()
    if reanalyze:
        run_pipeline(store, events)
    return {
        "files": sources,
        "ingested": len(all_events),
        "total_events": len(events),
        "findings": len(store.findings),
        "paths": len(store.paths),
    }


def ingest_bytes(
    data: bytes,
    filename: str,
    *,
    reanalyze: bool = True,
    replace: bool = False,
) -> dict:
    if replace:
        clear_events()
    events = enrich_events(parse_bytes(data, filename=filename))
    return _commit(events, source=filename, reanalyze=reanalyze, replace=False)


def _commit(
    events: list[NormalizedEvent],
    *,
    source: str,
    reanalyze: bool,
    replace: bool,
) -> dict:
    if replace:
        clear_events()
    inserted = save_events(events, source_file=source)
    all_events = load_events()
    if reanalyze:
        run_pipeline(store, all_events)
    return {
        "files": [source],
        "ingested": inserted,
        "total_events": len(all_events),
        "findings": len(store.findings) if store.ready else 0,
        "paths": len(store.paths) if store.ready else 0,
    }


def reload_from_db() -> dict:
    events = load_events()
    run_pipeline(store, events)
    return {
        "total_events": len(events),
        "findings": len(store.findings),
        "paths": len(store.paths),
        "ready": store.ready,
    }
