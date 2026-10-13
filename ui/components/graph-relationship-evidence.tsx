import type { UnifiedEdge } from "@/lib/graph-schema";

type EvidenceEdge = Pick<UnifiedEdge, "evidence" | "last_seen" | "traversable">;

const categories: Record<string, string> = {
  static: "Static / configured", static_scan: "Static / configured", static_evidence: "Static / configured",
  configured: "Static / configured", configured_target: "Static / configured", configured_delegation: "Static / configured",
  configuration: "Static / configured", recorded_configuration: "Static / configured",
  inferred: "Inferred", inferred_reachability: "Inferred",
  modeled: "Modeled", modeled_infrastructure: "Modeled",
  runtime_observed: "Runtime observed", runtime_blocked: "Runtime blocked",
};

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/** Present explicit receipt markers; a verb or traversal flag is not evidence. */
function evidenceType(evidence: Record<string, unknown>): string {
  const labels = new Set<string>();
  for (const value of [evidence.evidence_tier, evidence.evidence_basis, evidence.basis]) {
    const key = text(value);
    if (key && Object.hasOwn(categories, key)) labels.add(categories[key]!);
  }
  const sources = [evidence.source, evidence.data_source];
  if (sources.includes("source-ast")) labels.add("Static / configured");
  const runtimeSource = sources.some(source => typeof source === "string" && ["runtime-proxy", "runtime-identity", "runtime-feedback"].includes(source));
  if (runtimeSource && !labels.has("Runtime observed") && !labels.has("Runtime blocked")) labels.add("Runtime receipt");
  const unclassified = [evidence.evidence_tier, evidence.evidence_basis, evidence.basis].some(value => text(value));
  return labels.size > 1 ? "Mixed recorded evidence" : [...labels][0] ?? (unclassified ? "Unclassified" : "Not recorded");
}

export function GraphRelationshipEvidence({ edge }: { edge: EvidenceEdge }) {
  const evidence = edge.evidence ?? {};
  const receiptTimestamp = text(evidence.timestamp);
  return <div className="space-y-2 text-xs text-ink-secondary [overflow-wrap:anywhere]">
    <dl aria-label="Relationship evidence and freshness" className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1">
      <dt>Evidence type</dt><dd>{evidenceType(evidence)}</dd>
      <dt>Source observed at</dt><dd>{text(evidence.observed_at) ?? "Not recorded"}</dd>
      {receiptTimestamp && <><dt>Receipt timestamp</dt><dd>{receiptTimestamp}</dd></>}
      <dt>Graph last seen</dt><dd>{text(edge.last_seen) ?? "Not recorded"}</dd>
      <dt>Graph traversal</dt><dd>{edge.traversable === true ? "Eligible" : edge.traversable === false ? "Not enabled" : "Not recorded"}</dd>
    </dl>
    <p>Graph timestamps track the link record, not necessarily source activity. Traversal eligibility does not establish runtime reachability.</p>
  </div>;
}
