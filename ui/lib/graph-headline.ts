import type { FindingSeverityCounts, UnifiedGraphFlowSummary } from "@/lib/unified-graph-flow";

const SEVERITY_ORDER: (keyof FindingSeverityCounts)[] = ["critical", "high", "medium", "low", "unrated"];

type HeadlineSummary = Pick<UnifiedGraphFlowSummary, "findings" | "findingSeverity" | "kevListed">;

/** Severity and KEV status are separate axes: a high-severity KEV advisory is "1 high finding · 1 KEV-listed". */
export function formatGraphFindingCounts(summary: HeadlineSummary): string {
  const { findings, findingSeverity, kevListed } = summary;
  // Canvas-scoped: the estate's issue total lives in the overview and roll-up.
  const noun = findings === 1 ? "finding in view" : "findings in view";
  const buckets = SEVERITY_ORDER.filter((key) => findingSeverity[key] > 0);
  let text: string;
  if (findings === 0 || buckets.length === 0) text = `${findings.toLocaleString()} ${noun}`;
  else if (buckets.length === 1) text = `${findings.toLocaleString()} ${buckets[0]} ${noun}`;
  else text = `${findings.toLocaleString()} ${noun}: ${buckets.map((key) => `${findingSeverity[key].toLocaleString()} ${key}`).join(", ")}`;
  return kevListed > 0 ? `${text} · ${kevListed.toLocaleString()} KEV-listed` : text;
}

export function formatGraphHeadline(summary: HeadlineSummary, snapshotPaths: number): string {
  return `${formatGraphFindingCounts(summary)} · ${snapshotPaths.toLocaleString()} ${snapshotPaths === 1 ? "attack path" : "attack paths"} in snapshot (deduplicated)`;
}
