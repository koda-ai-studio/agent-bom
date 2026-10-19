import { hopReceiptCoverage } from "@/lib/hop-receipt-coverage";
import { evidenceTierLabel } from "@/lib/plain-labels";
import { countLabel } from "@/lib/count-label";
import type { FixFirstRiskReason, GraphAttackPath } from "@/lib/api-types";
import type { UnifiedNode } from "@/lib/graph-schema";
import { GraphHopEvidenceInspector } from "@/components/graph-hop-evidence-inspector";

const CONFIDENCE_LABELS: Readonly<Record<string, string>> = {
  verified: "hop receipts complete",
  likely: "likely",
  structural: "topology only",
  unassessed: "not assessed",
  disproven: "ruled unlikely",
};

function badgeTone(kind: string): string {
  if (kind === "runtime_observed") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  if (kind === "runtime_blocked") return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300";
  if (kind === "modeled_infrastructure") return "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300";
  if (kind === "stale_allowed" || kind === "bounded_analysis") return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
  return "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300";
}

export function AttackPathCorrelationProof({
  path,
  riskReasons = [],
  nodes = [],
}: {
  path: GraphAttackPath;
  riskReasons?: FixFirstRiskReason[] | undefined;
  nodes?: UnifiedNode[] | undefined;
}) {
  const receipts = Array.isArray(path.hop_evidence) ? path.hop_evidence.filter((receipt) => receipt && typeof receipt === "object") : [];
  const rankingFactors = path.ranking_factors && Array.isArray(path.ranking_factors.reasons) ? path.ranking_factors : null;

  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const anchors = path.hops
    .map((nodeId) => nodeById.get(nodeId))
    .filter((node): node is UnifiedNode => Boolean(node))
    .filter((node) => {
      const kind = node.entity_type.toLowerCase();
      return kind === "container" || kind === "package" || kind === "vulnerability" || kind === "finding";
    });
  const expectedHopCount = Math.max(path.hops.length - 1, 0);
  const coverage = hopReceiptCoverage(path);
  const pathEvidenceComplete = (path.reachability === "confirmed" || path.reachability === "likely") && coverage.complete !== null;
  const proofLabel = pathEvidenceComplete ? "Hop receipts complete" : "Hop receipts incomplete";
  const missingNodes = path.hops.filter((id) => !nodeById.has(id));
  const sourceCount = new Set(receipts.flatMap((receipt) =>
    Array.isArray(receipt?.source_snapshot_ids) ? receipt.source_snapshot_ids.filter(Boolean) : [],
  )).size;

  const kinds = new Map<string, string>();
  for (const receipt of receipts) {
    if (receipt.evidence_tier === "static_scan") kinds.set("static_scan", "Read from files or configuration");
    if (receipt.evidence_tier === "modeled_infrastructure") kinds.set("modeled_infrastructure", "Modeled infrastructure");
    if (receipt.runtime_observed_state === "observed") kinds.set("runtime_observed", "Runtime observed");
    if (receipt.runtime_observed_state === "blocked") kinds.set("runtime_blocked", "Runtime blocked");
    if (receipt.freshness === "stale_allowed") kinds.set("stale_allowed", "Stale allowed");
  }
  if (riskReasons.some((reason) => reason.kind === "runtime_blocked")) {
    kinds.set("runtime_blocked", "Gateway block observed");
  }
  if (path.analysis?.status && path.analysis.status !== "complete") {
    kinds.set("bounded_analysis", "Bounded analysis");
  }

  return (
    <section
      aria-label="Correlation path proof"
      data-testid="attack-path-correlation-proof"
      className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]/70 p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-[15px] font-semibold text-[color:var(--foreground)]">{proofLabel}</p>
          <p className="mt-0.5 text-[15px] text-[color:var(--text-tertiary)]">
            {coverage.summary}
          </p>
          {coverage.complete === null && coverage.gaps.length > 0 && <p className="mt-0.5 text-[15px] text-[color:var(--text-tertiary)]">Gaps: {coverage.gaps.join(", ")}</p>}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {[...kinds].map(([kind, label]) => (
            <span key={kind} className={`rounded-full border px-2 py-1 text-[15px] font-medium ${badgeTone(kind)}`}>
              {label}
            </span>
          ))}
        </div>
      </div>
      {missingNodes.length > 0 && <p role="status" className="mt-2 text-[15px] text-amber-700 dark:text-amber-300">{missingNodes.length} path nodes unavailable</p>}
      <details className="mt-2">
        <summary className="cursor-pointer py-1 text-[15px] font-medium text-[color:var(--text-secondary)]">Why this path ranks here</summary>
        {rankingFactors ? (
          <div data-testid="attack-path-ranking-factors" className="mt-2 space-y-2">
            <dl className="flex flex-wrap gap-1.5 text-[15px]">
              {[
                ["Basis", evidenceTierLabel(rankingFactors.evidence_tier)],
                ["KEV", rankingFactors.is_kev ? "yes" : "no"],
                ["Severity", rankingFactors.severity_scored ? rankingFactors.severity : "unscored"],
                ["Evidence", CONFIDENCE_LABELS[rankingFactors.evidence_confidence] ?? rankingFactors.evidence_confidence],
                ["Risk", `${rankingFactors.composite_risk}/100`],
              ].map(([term, value]) => (
                <div key={term} className="rounded-md border border-[color:var(--border-subtle)] px-2 py-0.5">
                  <dt className="inline text-[color:var(--text-tertiary)]">{term} </dt>
                  <dd className="inline font-medium text-[color:var(--foreground)]">{value}</dd>
                </div>
              ))}
            </dl>
            <ul className="list-disc space-y-1 pl-5 text-[color:var(--text-secondary)]">
              {rankingFactors.reasons.map((reason) => <li key={reason}>{reason}</li>)}
            </ul>
          </div>
        ) : null}
        {riskReasons.length ? <ul className="mt-2 space-y-2">{riskReasons.map((reason, index) => <li key={`${reason.kind}:${index}`}><strong>{reason.label}</strong><p className="text-[color:var(--text-secondary)]">{reason.detail}</p></li>)}</ul>
          : rankingFactors ? null
          : <p className="mt-2 text-[color:var(--text-secondary)]">The server supplied this queue order without ranking explanations. Priority does not establish effective access or exploitability.</p>}
      </details>
      <details className="mt-2 border-t border-[color:var(--border-subtle)] pt-2">
        <summary className="cursor-pointer py-1 text-[15px] text-[color:var(--text-secondary)]">Exact anchors · {anchors.length} artifacts · {sourceCount} source snapshots</summary>
        <div className="mt-2 flex flex-wrap gap-2">
        {anchors.map((node) => (
          <span key={node.id} className="max-w-full rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-1 font-mono text-[15px] text-[color:var(--foreground)] [overflow-wrap:anywhere]">
            {node.label || node.id}
          </span>
        ))}
        </div>
      </details>
      <details className="mt-2">
        <summary className="cursor-pointer py-1 text-[15px] font-medium text-[color:var(--text-secondary)]">Inspect {countLabel(expectedHopCount, "hop receipt")}</summary>
        <div className="mt-2">
          <GraphHopEvidenceInspector key={path.hops.join("->")} receipts={path.hop_evidence}
            hops={path.hops.map(id => ({ id, label: nodeById.get(id)?.label || id }))} />
        </div>
      </details>
    </section>
  );
}
