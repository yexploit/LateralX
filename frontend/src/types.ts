export type NodeType = "user" | "host" | "process" | "ip";
export type EvidenceKind = "observed" | "inferred";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  privilege?: string | null;
  sid?: string | null;
  status?: string | null;
  risk_score: number;
  rank?: number | null;
  meta?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  event_codes: number[];
  kind: EvidenceKind;
  weight: number;
  first_seen?: string | null;
  last_seen?: string | null;
  event_ids: string[];
  label?: string | null;
  meta?: Record<string, unknown>;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: Record<string, number>;
}

export interface NormalizedEvent {
  event_id: string;
  source: string;
  category: string;
  event_code: number;
  timestamp: string;
  host: string;
  user?: string | null;
  sid?: string | null;
  src_host?: string | null;
  dst_host?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  logon_type?: number | null;
  process_name?: string | null;
  process_id?: number | null;
  parent_process?: string | null;
  command_line?: string | null;
  target_user?: string | null;
  status?: string | null;
  privilege?: string | null;
  labels: string[];
  raw?: Record<string, unknown>;
}

export interface DetectionFinding {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  hosts: string[];
  users: string[];
  event_ids: string[];
  mitre_techniques: string[];
  timestamp: string;
  kind: EvidenceKind;
}

export interface AttackPathStep {
  step: number;
  timestamp: string;
  action: string;
  host: string;
  user?: string | null;
  detail: string;
  event_ids: string[];
  kind: EvidenceKind;
  confidence: number;
}

export interface AttackPath {
  id: string;
  name: string;
  severity: Severity;
  confidence: number;
  start_host: string;
  end_host: string;
  compromised_hosts: string[];
  steps: AttackPathStep[];
  findings: string[];
  summary: string;
  recommended_response: string[];
  timeline_start: string;
  timeline_end: string;
}

export interface InvestigationSummary {
  id: string;
  title: string;
  narrative: string;
  severity: Severity;
  confidence: number;
  attack_path_id?: string | null;
  key_entities: Record<string, string[]>;
  evidence_links: Record<string, string>[];
  recommended_response: string[];
  created_at: string;
}

export interface RankedEntity {
  rank: number;
  id: string;
  label: string;
  type: NodeType;
  score: number;
  connections: number;
  privilege?: string | null;
  tags: string[];
}

export interface DashboardStats {
  total_events: number;
  total_hosts: number;
  total_users: number;
  total_findings: number;
  critical_findings: number;
  attack_paths: number;
  observed_edges: number;
  inferred_edges: number;
  time_range_start?: string | null;
  time_range_end?: string | null;
  detection_rate: number;
  false_positive_rate: number;
  avg_latency_ms: number;
  path_accuracy: number;
}

export interface FilterCategory {
  id: string;
  label: string;
  hint: string;
}

export interface ReplayScenario {
  id: string;
  name: string;
  description: string;
  hosts: string[];
  expected_techniques: string[];
  status: string;
}

export interface ReplayResult {
  scenario_id: string;
  detected: boolean;
  findings_matched: string[];
  path_reconstructed: boolean;
  detection_rate: number;
  false_positives: number;
  latency_ms: number;
  path_accuracy: number;
  summary: string;
}

export interface PathSearchResult {
  paths: string[][];
  edges_used: string[];
  confidence: number;
}

export interface NodeDetail {
  node: GraphNode;
  edges: GraphEdge[];
  events: NormalizedEvent[];
  logon_types: Record<string, string>;
}
