import type { GraphCorrelationOutcome } from "@/components/graph-correlation-workflow";
import type { FixFirstPathCard } from "@/lib/api";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";
import { buildCorrelationRemediationHref, completeDirectedHopCount, correlationOutcomeMatchesOutput } from "@/lib/security-graph-focus";

/** The correlation summary for the selected path, or null when its evidence does not belong to this output. */
export function buildCorrelationOutcome({ path, card, actions, nodeById, scanId, graphScanId, fixFirstScanId }: {
  path: AttackPath | null;
  card: FixFirstPathCard | null;
  actions: { title: string; href: string }[];
  nodeById: Map<string, UnifiedNode>;
  scanId: string;
  graphScanId: string | undefined;
  fixFirstScanId: string | undefined;
}): GraphCorrelationOutcome | null {
    if (
      !path ||
      !correlationOutcomeMatchesOutput(scanId, graphScanId, fixFirstScanId)
    ) return null;
    const labels = card?.sequence_labels ?? path.hops.map((hop) => nodeById.get(hop)?.label ?? hop);
    const packageNode = path.hops
      .map((hop) => nodeById.get(hop))
      .find((node) => node?.entity_type === "package");
    const finding = card?.affected.finding_labels?.[0] ?? path.vuln_ids[0];
    const reasons = card?.risk_reasons ?? [];
    const hopReceipts = path.hop_evidence ?? [];
    const directedHopCount = completeDirectedHopCount(path);
    if (directedHopCount === null) return null;
    const action = card?.next_actions?.[0] ?? actions[0];
    const actionIsRemediation = action?.href.split("?", 1)[0] === "/remediation";
    return {
      scanId: scanId,
      summary: finding && packageNode?.label
        ? `${finding} in ${packageNode.label} appears on this correlated path. Inspect the evidence and conditions at each hop.`
        : "Review the recorded relationships and per-hop evidence for this selected path.",
      source: labels[0] ?? path.source,
      target: labels.at(-1) ?? path.target,
      finding,
      packageName: packageNode?.label,
      risk: path.composite_risk,
      hops: directedHopCount,
      runtimeObserved: reasons.some((reason) => reason.kind === "runtime_observed") || hopReceipts.some((receipt) => receipt.runtime_observed_state === "observed"),
      runtimeBlocked: reasons.some((reason) => reason.kind === "runtime_blocked") || hopReceipts.some((receipt) => receipt.runtime_observed_state === "blocked"),
      action: action ? {
        title: actionIsRemediation
          ? `Open ${packageNode?.label ?? finding ?? "finding"} remediation`
          : action.title,
        href: actionIsRemediation
          ? buildCorrelationRemediationHref(action.href, scanId, finding, packageNode?.label)
          : action.href,
      } : undefined,
    };
}
