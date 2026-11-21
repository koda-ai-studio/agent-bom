import type { LineageNodeData } from "@/components/lineage-nodes";
import { nodeContextMarkers } from "@/lib/attack-path-graph-markers";
import { severityChipClass } from "@/lib/severity";
import { nodeRiskAssessment, nodeRiskLabel } from "@/lib/node-risk-assessment";

export function graphSemanticRiskLabel(score: number | undefined, assessment: unknown): string {
  if (nodeRiskAssessment(assessment).status !== "assessed" && typeof score === "number" && Number.isFinite(score)) {
    return `${score.toFixed(1)} (assessment not recorded)`;
  }
  return nodeRiskLabel(score, assessment);
}

/** Attribute markers and finding counts are backend facts, not extra entities. */
export function GraphAttributeBadges({ data }: { data: LineageNodeData }) {
  const markers = nodeContextMarkers(data.attributes ?? {});
  const aggregate = data.rollup?.aggregate;
  const count = aggregate?.issue_count;
  const exposed = typeof aggregate?.exposed_count === "number" ? aggregate.exposed_count : 0;
  const risk = typeof data.riskScore === "number" && Number.isFinite(data.riskScore) ? graphSemanticRiskLabel(data.riskScore, data.riskAssessment) : null;
  if (!markers.length && !data.isKev && count == null && !exposed && !data.evidenceSources?.length && !data.semanticLayerIssue && risk === null) return null;
  return <div data-semantic-badges className="mb-2 flex max-w-full flex-wrap justify-center gap-1 text-xs text-ink-secondary">
    {data.semanticLayerIssue && <span data-semantic-layer-error className="rounded border border-amber-500 bg-surface px-1.5 py-0.5">{data.semanticLayerIssue}</span>}
    {risk !== null && <span data-semantic-risk className="rounded border border-outline-strong bg-surface px-1.5 py-0.5">Risk {risk}</span>}
    {data.evidenceSources?.map(source => <span key={source} data-evidence-source={source} className="rounded border border-outline-strong bg-surface px-1.5 py-0.5">{source}</span>)}
    {markers.map(marker => <span key={marker.kind} title={marker.label} className="rounded border border-outline-strong bg-surface px-1.5 py-0.5">
      {marker.kind === "privileged" ? "Privileged" : marker.kind === "sensitive" ? "Sensitive data" : marker.kind === "internet" ? "Internet-exposed" : "Crown jewel"}
    </span>)}
    {exposed > 0 && <span className="rounded border border-outline-strong bg-surface px-1.5 py-0.5">{exposed} exposed {exposed === 1 ? "entity" : "entities"}</span>}
    {typeof count === "number" && (data.onExploreFindings
      ? <button type="button" data-finding-count-source="rollup" onClick={event => { event.stopPropagation(); data.onExploreFindings!(); }} className={`nodrag nopan rounded border px-1.5 py-0.5 ${severityChipClass(aggregate?.worst_severity ?? "unknown")}`}>Findings ({count})</button>
      : <span data-finding-count-source="rollup" className={`rounded border px-1.5 py-0.5 ${severityChipClass(aggregate?.worst_severity ?? "unknown")}`}>Findings ({count})</span>)}
    {data.isKev && <span title="CISA Known Exploited Vulnerabilities" className="rounded border border-red-500 bg-red-500/10 px-1.5 py-0.5 text-red-700 dark:text-red-300">KEV</span>}
  </div>;
}
