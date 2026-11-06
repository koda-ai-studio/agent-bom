import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

export interface TopRisk {
  id: string;
  label: string;
  nodeType: string;
  severity?: string | undefined;
  riskScore?: number | undefined;
  kev: boolean;
  /** Assets sharing this name; a repeated finding is one line of attention, not six. */
  count: number;
}

export const TOP_RISK_LIMIT = 6;
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const severityOf = (data: LineageNodeData) => SEVERITY_RANK[data.severity?.toLowerCase() ?? ""] ?? 0;
const scoreOf = (data: LineageNodeData) => typeof data.riskScore === "number" && Number.isFinite(data.riskScore) ? data.riskScore : 0;

/**
 * What the records say is riskiest: recorded risk score, then severity, then a known-exploited listing.
 * An asset with neither a score nor a severity is never ranked, so a clean estate shows no list at all.
 */
export function rankTopRisks(nodes: Node<LineageNodeData>[], limit = TOP_RISK_LIMIT): TopRisk[] {
  const scored = nodes.filter(node => !node.data.displayOnly && (scoreOf(node.data) > 0 || severityOf(node.data) > 0));
  scored.sort((a, b) => scoreOf(b.data) - scoreOf(a.data) || severityOf(b.data) - severityOf(a.data)
    || Number(b.data.isKev === true) - Number(a.data.isKev === true) || a.id.localeCompare(b.id));
  const byLabel = new Map<string, TopRisk>();
  for (const { id, data } of scored) {
    const seen = byLabel.get(data.label);
    if (seen) { seen.count++; continue; }
    byLabel.set(data.label, { id, label: data.label, nodeType: data.nodeType, severity: severityOf(data) > 0 ? data.severity!.toLowerCase() : undefined, riskScore: scoreOf(data) || undefined, kev: data.isKev === true, count: 1 });
  }
  return [...byLabel.values()].slice(0, limit);
}
