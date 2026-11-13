import type { AttackPath } from "@/lib/graph-schema";
import { countLabel } from "@/lib/count-label";
import { completeDirectedHopCount } from "@/lib/security-graph-focus";

type Receipt = NonNullable<NonNullable<AttackPath["hop_evidence"]>[number]>;

const RECEIPT_CHECKS: Array<[string, (receipt: Receipt) => boolean]> = [
  ["evidence marked incomplete by its source", receipt => receipt.complete !== true],
  ["evidence was truncated", receipt => receipt.truncated !== false],
  ["link direction not recorded", receipt => receipt.direction !== "directed"],
  ["link not confirmed as traversable", receipt => receipt.traversable !== true],
  ["a runtime attempt was blocked or failed", receipt => receipt.runtime_observed_state === "blocked" || receipt.runtime_outcome === "blocked" || receipt.runtime_outcome === "failed"],
  ["evidence age unknown", receipt => receipt.freshness !== "fresh"],
  ["source of the link not recorded", receipt => receipt.relationship_provenance !== "recorded"],
  ["entity identity may be outdated", receipt => receipt.correlation_identity_status !== "current"],
  ["source scan not recorded", receipt => !Array.isArray(receipt.source_snapshot_ids) || !receipt.source_snapshot_ids.some(id => typeof id === "string" && id.trim())],
];

const ANALYSIS_GAPS: Readonly<Record<string, string>> = {
  not_recorded: "no record that the full path was analyzed",
  limited: "path analysis stopped at its limits",
  skipped: "path analysis was skipped",
  failed: "path analysis failed",
};

function coverageSummary(expected: number, recorded: number, evidenced: number, complete: number | null): string {
  const hops = countLabel(expected, "hop");
  if (complete !== null) return `${complete} of ${hops} evidenced as directed and traversable`;
  if (recorded === 0) return `No evidence recorded for ${hops}`;
  const missing = expected - recorded;
  return `${evidenced} of ${hops} fully evidenced${missing > 0 ? ` · ${missing} with no evidence recorded` : ""}`;
}

function alignedReceipts(path: AttackPath): Array<{ receipt: Receipt; index: number }> {
  const expected = Math.max(path.hops.length - 1, 0);
  const receipts = Array.isArray(path.hop_evidence) ? path.hop_evidence : [];
  const aligned: Array<{ receipt: Receipt; index: number }> = [];
  for (let index = 0; index < expected; index += 1) {
    const receipt = receipts[index];
    if (receipt && typeof receipt === "object" && receipt.source_node_id === path.hops[index] && receipt.target_node_id === path.hops[index + 1]) aligned.push({ receipt, index });
  }
  return aligned;
}

function fullyEvidenced(path: AttackPath, { receipt, index }: { receipt: Receipt; index: number }): boolean {
  return receipt.relationship === path.edges[index] && !RECEIPT_CHECKS.some(([, failed]) => failed(receipt));
}

export const hopKey = (source: string, target: string) => `${source}\u0000${target}`;

/** Hops (`hopKey`) whose receipt passes every check the coverage summary counts as fully evidenced. */
export function receiptedHops(path: AttackPath): Set<string> {
  return new Set(alignedReceipts(path).filter(item => fullyEvidenced(path, item)).map(({ index }) => hopKey(path.hops[index]!, path.hops[index + 1]!)));
}

/** Count the evidence actually recorded for each hop and say, in plain words, why it falls short of complete proof. */
export function hopReceiptCoverage(path: AttackPath) {
  const expected = Math.max(path.hops.length - 1, 0);
  const aligned = alignedReceipts(path);
  const gaps = RECEIPT_CHECKS.filter(([, failed]) => aligned.some(({ receipt }) => failed(receipt))).map(([label]) => label);
  if (aligned.some(({ receipt, index }) => receipt.relationship !== path.edges[index])) gaps.push("recorded link type differs from the path");
  const analysis = path.analysis?.status || "not_recorded";
  if (analysis !== "complete") gaps.push(ANALYSIS_GAPS[analysis] ?? `path analysis ${analysis.replaceAll("_", " ")}`);
  const evidenced = aligned.filter(item => fullyEvidenced(path, item)).length;
  const complete = completeDirectedHopCount(path);
  const summary = coverageSummary(expected, aligned.length, evidenced, complete);
  return { expected, recorded: aligned.length, evidenced, complete, gaps, summary };
}
