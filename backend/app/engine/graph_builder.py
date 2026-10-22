"""Build host/identity attack graphs with NetworkX."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

import networkx as nx

from app.models.schemas import (
    AttackGraph,
    EvidenceKind,
    GraphEdge,
    GraphNode,
    NodeType,
    NormalizedEvent,
    RankedEntity,
)
from app.engine.normalizer import logon_type_name


def _user_id(user: str) -> str:
    return f"user:{user.lower()}"


def _host_id(host: str) -> str:
    return f"host:{host.lower()}"


def _clean_user(user: str) -> str:
    return user.split("\\")[-1] if "\\" in user else user


def build_attack_graph(events: list[NormalizedEvent]) -> tuple[AttackGraph, nx.DiGraph]:
    G: nx.DiGraph = nx.DiGraph()
    edge_bucket: dict[tuple[str, str], dict] = {}

    for ev in events:
        if ev.user:
            uid = _user_id(ev.user)
            if uid not in G:
                G.add_node(
                    uid,
                    label=_clean_user(ev.user),
                    type=NodeType.USER.value,
                    privilege=ev.privilege,
                    sid=ev.sid,
                    status=ev.status,
                    risk=0.0,
                )
            else:
                if ev.privilege and (not G.nodes[uid].get("privilege") or ev.privilege == "SYSTEM"):
                    G.nodes[uid]["privilege"] = ev.privilege
                if ev.sid:
                    G.nodes[uid]["sid"] = ev.sid

        host_name = ev.host
        hid = _host_id(host_name)
        if hid not in G:
            G.add_node(
                hid,
                label=host_name,
                type=NodeType.HOST.value,
                privilege=None,
                sid=None,
                status="active",
                risk=0.0,
            )

        # User activity on host
        if ev.user:
            _accumulate_edge(
                edge_bucket,
                _user_id(ev.user),
                hid,
                ev,
                label=logon_type_name(ev.logon_type) if ev.logon_type else ev.category.value,
            )

        # Host-to-host lateral edges
        src = ev.src_host
        dst = ev.dst_host or (ev.host if ev.src_host and ev.src_host.lower() != ev.host.lower() else None)
        if src and dst and src.lower() != dst.lower():
            kind = EvidenceKind.OBSERVED
            if "lateral" in ev.labels or ev.logon_type in {3, 10} or ev.event_code in {4624, 3}:
                _accumulate_edge(
                    edge_bucket,
                    _host_id(src),
                    _host_id(dst),
                    ev,
                    label=f"EID {ev.event_code}",
                    kind=kind,
                )
                if _host_id(src) not in G:
                    G.add_node(
                        _host_id(src),
                        label=src,
                        type=NodeType.HOST.value,
                        privilege=None,
                        sid=None,
                        status="active",
                        risk=0.0,
                    )
                if _host_id(dst) not in G:
                    G.add_node(
                        _host_id(dst),
                        label=dst,
                        type=NodeType.HOST.value,
                        privilege=None,
                        sid=None,
                        status="active",
                        risk=0.0,
                    )

    # Infer 2-hop host paths (A→B→C ⇒ inferred A→C) for investigation context
    observed_pairs = {
        (s, t)
        for (s, t), meta in edge_bucket.items()
        if meta["kind"] == EvidenceKind.OBSERVED and s.startswith("host:") and t.startswith("host:")
    }
    inferred = 0
    for a, b in list(observed_pairs):
        for b2, c in list(observed_pairs):
            if b == b2 and a != c and (a, c) not in observed_pairs and inferred < 40:
                bridge = b.split(":", 1)[-1]
                edge_bucket[(a, c)] = {
                    "event_codes": [],
                    "event_ids": [],
                    "kind": EvidenceKind.INFERRED,
                    "weight": 0.55,
                    "first_seen": None,
                    "last_seen": None,
                    "label": "inferred path",
                    "meta": {"reason": f"multi-hop via {bridge}"},
                }
                inferred += 1

    for (src, dst), meta in edge_bucket.items():
        if src not in G or dst not in G:
            continue
        G.add_edge(src, dst, **meta)
        # risk bump
        bump = 2.5 if meta["kind"] == EvidenceKind.OBSERVED else 1.0
        G.nodes[src]["risk"] = float(G.nodes[src].get("risk", 0)) + bump * meta.get("weight", 1)
        G.nodes[dst]["risk"] = float(G.nodes[dst].get("risk", 0)) + bump * meta.get("weight", 1) * 0.8

    # Privilege-weighted risk
    for n, data in G.nodes(data=True):
        if data.get("privilege") == "SYSTEM":
            data["risk"] = float(data.get("risk", 0)) + 8
        if data.get("type") == NodeType.HOST.value and "dc" in data.get("label", "").lower():
            data["risk"] = float(data.get("risk", 0)) + 6

    nodes: list[GraphNode] = []
    for nid, data in G.nodes(data=True):
        nodes.append(
            GraphNode(
                id=nid,
                label=data.get("label", nid),
                type=NodeType(data.get("type", "host")),
                privilege=data.get("privilege"),
                sid=data.get("sid"),
                status=data.get("status"),
                risk_score=round(float(data.get("risk", 0)), 2),
                meta={},
            )
        )

    edges: list[GraphEdge] = []
    for i, (src, dst, data) in enumerate(G.edges(data=True)):
        edges.append(
            GraphEdge(
                id=f"e-{i}-{src}-{dst}",
                source=src,
                target=dst,
                event_codes=list(data.get("event_codes") or []),
                kind=data.get("kind", EvidenceKind.OBSERVED),
                weight=float(data.get("weight", 1)),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                event_ids=list(data.get("event_ids") or []),
                label=data.get("label"),
                meta=dict(data.get("meta") or {}),
            )
        )

    stats = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "user_count": sum(1 for n in nodes if n.type == NodeType.USER),
        "host_count": sum(1 for n in nodes if n.type == NodeType.HOST),
        "observed_edges": sum(1 for e in edges if e.kind == EvidenceKind.OBSERVED),
        "inferred_edges": sum(1 for e in edges if e.kind == EvidenceKind.INFERRED),
    }
    return AttackGraph(nodes=nodes, edges=edges, stats=stats), G


def _accumulate_edge(
    bucket: dict,
    src: str,
    dst: str,
    ev: NormalizedEvent,
    *,
    label: str,
    kind: EvidenceKind = EvidenceKind.OBSERVED,
) -> None:
    key = (src, dst)
    if key not in bucket:
        bucket[key] = {
            "event_codes": [],
            "event_ids": [],
            "kind": kind,
            "weight": 1.0,
            "first_seen": ev.timestamp,
            "last_seen": ev.timestamp,
            "label": label,
            "meta": {},
        }
    meta = bucket[key]
    if ev.event_code not in meta["event_codes"]:
        meta["event_codes"].append(ev.event_code)
    meta["event_ids"].append(ev.event_id)
    meta["weight"] = float(meta["weight"]) + 0.35
    fs: datetime | None = meta["first_seen"]
    ls: datetime | None = meta["last_seen"]
    if fs is None or ev.timestamp < fs:
        meta["first_seen"] = ev.timestamp
    if ls is None or ev.timestamp > ls:
        meta["last_seen"] = ev.timestamp
    # Prefer more specific labels
    if "lateral" in ev.labels or ev.logon_type in {3, 10}:
        meta["label"] = label


def rank_entities(graph: AttackGraph, limit: int = 20) -> tuple[list[RankedEntity], list[RankedEntity]]:
    degree: dict[str, int] = defaultdict(int)
    for e in graph.edges:
        degree[e.source] += 1
        degree[e.target] += 1

    users = [n for n in graph.nodes if n.type == NodeType.USER]
    hosts = [n for n in graph.nodes if n.type == NodeType.HOST]

    def to_ranked(nodes: list[GraphNode]) -> list[RankedEntity]:
        scored = sorted(nodes, key=lambda n: (n.risk_score, degree[n.id]), reverse=True)
        out: list[RankedEntity] = []
        for i, n in enumerate(scored[:limit], start=1):
            tags = []
            if n.privilege == "SYSTEM":
                tags.append("SYSTEM")
            if n.risk_score >= 15:
                tags.append("high-risk")
            out.append(
                RankedEntity(
                    rank=i,
                    id=n.id,
                    label=n.label,
                    type=n.type,
                    score=n.risk_score,
                    connections=degree[n.id],
                    privilege=n.privilege,
                    tags=tags,
                )
            )
        return out

    return to_ranked(users), to_ranked(hosts)


def search_paths(G: nx.DiGraph, source: str, target: str, max_hops: int = 6) -> list[list[str]]:
    if source not in G or target not in G:
        # try resolving bare labels
        source = _resolve(G, source)
        target = _resolve(G, target)
    if source not in G or target not in G:
        return []
    paths: list[list[str]] = []
    try:
        for path in nx.all_simple_paths(G, source, target, cutoff=max_hops):
            paths.append(path)
            if len(paths) >= 8:
                break
    except (nx.NetworkXError, nx.NodeNotFound):
        return []
    return paths


def _resolve(G: nx.DiGraph, name: str) -> str:
    raw = name.strip().lower()
    if raw in G:
        return raw
    for prefix in ("user:", "host:"):
        candidate = f"{prefix}{raw}"
        if candidate in G:
            return candidate
    for nid, data in G.nodes(data=True):
        if data.get("label", "").lower() == raw:
            return nid
        if raw in nid:
            return nid
    return name
