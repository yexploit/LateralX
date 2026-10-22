import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { AttackGraph, GraphNode } from "../types";

type FGNode = GraphNode & { x?: number; y?: number };
type FGLink = {
  id: string;
  source: string | FGNode;
  target: string | FGNode;
  label?: string | null;
  kind: string;
  event_codes: number[];
};

interface Props {
  graph: AttackGraph;
  highlightPath?: string[];
  selectedId?: string | null;
  onSelect: (node: GraphNode, coords: { x: number; y: number }) => void;
}

export function AttackGraphView({ graph, highlightPath = [], selectedId, onSelect }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<any>(null);
  const [size, setSize] = useState({ w: 800, h: 500 });

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      setSize({ w: el.clientWidth, h: el.clientHeight });
    });
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);

  const data = useMemo(() => {
    const nodes: FGNode[] = graph.nodes.map((n) => ({ ...n }));
    const links: FGLink[] = graph.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label || (e.event_codes.length ? e.event_codes.join(",") : ""),
      kind: e.kind,
      event_codes: e.event_codes,
    }));
    return { nodes, links };
  }, [graph]);

  const pathSet = useMemo(() => new Set(highlightPath), [highlightPath]);

  const paintNode = useCallback(
    (node: FGNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const r = node.type === "host" ? 8 : 6;
      const x = node.x || 0;
      const y = node.y || 0;
      const selected = node.id === selectedId;
      const onPath = pathSet.has(node.id);

      ctx.beginPath();
      if (node.type === "host") {
        ctx.save();
        ctx.translate(x, y);
        ctx.rotate(Math.PI / 4);
        ctx.rect(-r, -r, r * 2, r * 2);
        ctx.restore();
      } else {
        ctx.arc(x, y, r, 0, Math.PI * 2);
      }

      if (node.type === "host") {
        ctx.fillStyle = node.label.toLowerCase().includes("dc") ? "#f0a202" : "#3dcf7a";
      } else if (node.privilege === "SYSTEM") {
        ctx.fillStyle = "#ff5d6c";
      } else {
        ctx.fillStyle = "#5b9cff";
      }
      ctx.fill();

      if (selected || onPath) {
        ctx.strokeStyle = selected ? "#2dd4a8" : "#f0a202";
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
      }

      const label = node.label;
      const fontSize = 11 / globalScale;
      ctx.font = `${fontSize}px Outfit, sans-serif`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillStyle = "rgba(232, 242, 236, 0.9)";
      ctx.fillText(label, x, y + r + 2);
    },
    [pathSet, selectedId]
  );

  const paintLink = useCallback(
    (link: FGLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const src = link.source as FGNode;
      const tgt = link.target as FGNode;
      if (src.x == null || tgt.x == null) return;

      const inferred = link.kind === "inferred";
      ctx.beginPath();
      ctx.moveTo(src.x, src.y || 0);
      ctx.lineTo(tgt.x, tgt.y || 0);
      ctx.strokeStyle = inferred ? "rgba(196, 163, 90, 0.75)" : "rgba(45, 212, 168, 0.65)";
      ctx.setLineDash(inferred ? [4 / globalScale, 4 / globalScale] : []);
      ctx.lineWidth = (inferred ? 1.2 : 1.6) / globalScale;
      ctx.stroke();
      ctx.setLineDash([]);

      if (link.label) {
        const mx = ((src.x || 0) + (tgt.x || 0)) / 2;
        const my = ((src.y || 0) + (tgt.y || 0)) / 2;
        const fontSize = 9 / globalScale;
        ctx.font = `${fontSize}px IBM Plex Mono, monospace`;
        ctx.fillStyle = "rgba(143, 168, 155, 0.95)";
        ctx.textAlign = "center";
        ctx.fillText(String(link.label), mx, my);
      }
    },
    []
  );

  useEffect(() => {
    const fg = fgRef.current;
    if (!fg) return;
    fg.d3Force("charge")?.strength(-180);
    fg.d3Force("link")?.distance(90);
  }, [data]);

  if (!graph.nodes.length) {
    return (
      <div className="graph-wrap" ref={wrapRef}>
        <div className="empty">No nodes match this filter. Clear filters or search again.</div>
      </div>
    );
  }

  return (
    <div className="graph-wrap" ref={wrapRef}>
      <ForceGraph2D
        ref={fgRef}
        width={size.w}
        height={size.h}
        graphData={data}
        nodeId="id"
        backgroundColor="rgba(0,0,0,0)"
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        linkCanvasObjectMode={() => "replace"}
        linkCanvasObject={paintLink as any}
        nodeCanvasObject={paintNode as any}
        nodePointerAreaPaint={(node: FGNode, color: string, ctx: CanvasRenderingContext2D) => {
          const r = 10;
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(node.x || 0, node.y || 0, r, 0, Math.PI * 2);
          ctx.fill();
        }}
        onNodeClick={(node: FGNode, event: MouseEvent) => {
          const rect = wrapRef.current?.getBoundingClientRect();
          onSelect(node, {
            x: event.clientX - (rect?.left || 0) + 12,
            y: event.clientY - (rect?.top || 0) + 12,
          });
        }}
        cooldownTicks={80}
      />
      <div className="graph-legend">
        <span>
          <i className="dot host" /> Host
        </span>
        <span>
          <i className="dot user" /> User
        </span>
        <span>
          <i className="dot observed" /> Observed edge
        </span>
        <span>
          <i className="dot inferred" /> Inferred edge
        </span>
      </div>
    </div>
  );
}
