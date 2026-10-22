"""Quick regression check for the LateralX pipeline + API contracts."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.engine.pipeline import replay_scenario, run_pipeline
from app.engine.graph_builder import search_paths
from app.store import InvestigationStore


def main() -> None:
    store = InvestigationStore()
    run_pipeline(store)
    assert store.ready
    assert store.stats and store.stats.total_events >= 20
    assert store.findings, "expected detections"
    assert store.paths and len(store.paths[0].steps) >= 5
    assert store.graph and len(store.graph.nodes) >= 5
    G = store._nx  # type: ignore[attr-defined]
    paths = search_paths(G, "workstation-01", "dc-01")
    assert paths, "expected host path workstation-01 → dc-01"
    result = replay_scenario(store, "scenario-3host-dcsync")
    assert result.detected
    assert result.path_reconstructed
    print("smoke_test OK")
    print(
        f"events={store.stats.total_events} findings={len(store.findings)} "
        f"detection_rate={store.stats.detection_rate} path_accuracy={store.stats.path_accuracy}"
    )


if __name__ == "__main__":
    main()
