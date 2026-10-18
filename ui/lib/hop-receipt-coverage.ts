import type { AttackPath } from "@/lib/graph-schema";
import { countLabel } from "@/lib/count-label";
import { completeDirectedHopCount } from "@/lib/security-graph-focus";

type Receipt = NonNullable<NonNullable<AttackPath["hop_evidence"]>[number]>;

const RECEIPT_CHECKS: Array<[string, (receipt: Receipt) => boolean]> = [
  ["receipt marked incomplete", receipt => receipt.complete !== true],
  ["receipt truncated", receipt => receipt.truncated !== false],
  ["not directed", receipt => receipt.direction !== "directed"],
  ["not traversable", receipt => receipt.traversable !== true],
  ["runtime blocked or failed", receipt => receipt.runtime_observed_state === "blocked" || receipt.runtime_outcome === "blocked" || receipt.runtime_outcome === "failed"],
  ["freshness not established", receipt => receipt.freshness !== "fresh"],
  ["relationship provenance unavailable", receipt => receipt.relationship_provenance !== "recorded"],
  ["correlation identity not current", receipt => receipt.correlation_identity_status !== "current"],
  ["source snapshot missing", receipt => !Array.isArray(receipt.source_snapshot_ids) || !receipt.source_snapshot_ids.some(id => typeof id === "string" && id.trim())],
];

/** Count the receipts actually recorded for each hop and name why they fall short of complete proof. */
export function hopReceiptCoverage(path: AttackPath) {
  const expected = Math.max(path.hops.length - 1, 0);
  const receipts = Array.isArray(path.hop_evidence) ? path.hop_evidence : [];
  const aligned: Array<{ receipt: Receipt; index: number }> = [];
  for (let index = 0; index < expected; index += 1) {
    const receipt = receipts[index];
    if (receipt && typeof receipt === "object" && receipt.source_node_id === path.hops[index] && receipt.target_node_id === path.hops[index + 1]) aligned.push({ receipt, index });
  }
  const gaps = RECEIPT_CHECKS.filter(([, failed]) => aligned.some(({ receipt }) => failed(receipt))).map(([label]) => label);
  if (aligned.some(({ receipt, index }) => receipt.relationship !== path.edges[index])) gaps.push("relationship differs from path edge");
  if (path.analysis?.status !== "complete") gaps.push(`path analysis ${(path.analysis?.status || "not_recorded").replaceAll("_", " ")}`);
  const evidenced = aligned.filter(({ receipt, index }) => receipt.relationship === path.edges[index] && !RECEIPT_CHECKS.some(([, failed]) => failed(receipt))).length;
  const complete = completeDirectedHopCount(path);
  const summary = complete !== null
    ? `${complete}/${expected} directed traversable hops evidenced`
    : `${evidenced}/${expected} hops fully evidenced · ${aligned.length} of ${countLabel(expected, "hop receipt")} recorded`;
  return { expected, recorded: aligned.length, evidenced, complete, gaps, summary };
}
