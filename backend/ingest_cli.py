#!/usr/bin/env python3
"""CLI: ingest real telemetry into LateralX.

Examples:
  python ingest_cli.py Security.evtx
  python ingest_cli.py ./logs/ --replace
  python ingest_cli.py events.json events2.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.db import init_db
from app.ingest.service import ingest_path, ingest_paths, reload_from_db
from app.store import store


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest Windows/Sysmon telemetry into LateralX")
    parser.add_argument("paths", nargs="+", help="EVTX/XML/JSON/JSONL/CSV files or directories")
    parser.add_argument("--replace", action="store_true", help="Clear existing events first")
    parser.add_argument("--no-analyze", action="store_true", help="Ingest only; skip analysis")
    args = parser.parse_args()

    init_db()
    paths = [Path(p) for p in args.paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print("Not found:", ", ".join(missing), file=sys.stderr)
        return 1

    reanalyze = not args.no_analyze
    if len(paths) == 1:
        result = ingest_path(paths[0], reanalyze=reanalyze, replace=args.replace)
    else:
        files: list[Path] = []
        for p in paths:
            if p.is_dir():
                files.extend(p.rglob("*.*"))
            else:
                files.append(p)
        result = ingest_paths(files, reanalyze=reanalyze, replace=args.replace)

    if args.no_analyze:
        reload_from_db()

    print("Ingest complete")
    for k, v in result.items():
        print(f"  {k}: {v}")
    if store.stats:
        print(
            f"  findings={store.stats.total_findings} "
            f"paths={store.stats.attack_paths} "
            f"hosts={store.stats.total_hosts}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
