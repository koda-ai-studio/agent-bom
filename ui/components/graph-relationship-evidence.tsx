import { graphEdgeEvidenceLabel } from "@/lib/graph-edge-evidence";
import type { UnifiedEdge } from "@/lib/graph-schema";

type EvidenceEdge = Pick<UnifiedEdge, "evidence" | "last_seen" | "traversable" | "source_scan_id">;

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

export function GraphRelationshipEvidence({ edge, compact = false }: { edge: EvidenceEdge; compact?: boolean }) {
  const evidence = edge.evidence ?? {};
  const receiptTimestamp = text(evidence.timestamp);
  return <div className="space-y-2 text-xs text-ink-secondary [overflow-wrap:anywhere]">
    <dl aria-label="Relationship evidence and freshness" className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1">
      <dt>Evidence type</dt><dd>{graphEdgeEvidenceLabel(edge)}</dd>
      <dt>Source observed at</dt><dd>{text(evidence.observed_at) ?? "Not recorded"}</dd>
      {receiptTimestamp && <><dt>Receipt timestamp</dt><dd>{receiptTimestamp}</dd></>}
      <dt>Graph last seen</dt><dd>{text(edge.last_seen) ?? "Not recorded"}</dd>
      <dt>Graph traversal</dt><dd>{edge.traversable === true ? "Eligible" : edge.traversable === false ? "Not enabled" : "Not recorded"}</dd>
    </dl>
    {!compact && <p>Graph timestamps track the link record, not necessarily source activity. Traversal eligibility does not establish runtime reachability.</p>}
  </div>;
}
