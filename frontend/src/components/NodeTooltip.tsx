import type { GraphNode } from "../types";

interface Props {
  node: GraphNode;
  x: number;
  y: number;
  onSearch: () => void;
  onClose: () => void;
}

export function NodeTooltip({ node, x, y, onSearch, onClose }: Props) {
  return (
    <div className="tooltip-card" style={{ left: Math.min(x, window.innerWidth - 340), top: y }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
        <h3>{node.label}</h3>
        <button className="btn btn-ghost" onClick={onClose} aria-label="Close">
          ✕
        </button>
      </div>
      <dl>
        <dt>Type</dt>
        <dd>{node.type}</dd>
        <dt>Privilege</dt>
        <dd>{node.privilege || "—"}</dd>
        <dt>SID</dt>
        <dd>{node.sid || "—"}</dd>
        <dt>Status</dt>
        <dd>{node.status || "—"}</dd>
        <dt>Risk</dt>
        <dd>{node.risk_score.toFixed(1)}</dd>
      </dl>
      <div className="list-actions">
        <button className="btn btn-primary" onClick={onSearch}>
          Search
        </button>
      </div>
    </div>
  );
}
