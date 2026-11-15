"use client";

import type { GraphFreshness } from "@/lib/api-contracts/findings";
import type { GraphCollectionCoverage } from "@/lib/api-contracts/scan-inventory";

/** A previous graph generation's recorded time for display; null when absent or unparseable. */
function recordedAt(iso: string | undefined): string | null {
  const parsed = new Date(iso?.trim() || NaN);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toLocaleString();
}

export function GraphProjectionNotice({ coverage, onRetry }: {
  coverage?: GraphCollectionCoverage | undefined;
  onRetry: () => void;
}) {
  if (coverage?.refresh_status !== "building") return null;
  const asOf = recordedAt(coverage.as_of);
  return <div role="status" className="flex flex-wrap items-center justify-between gap-2 border-b border-outline px-4 py-2 text-sm text-ink-secondary">
    <span>Updating graph · {asOf ? `showing data from ${asOf}` : "showing the previous complete view"}</span>
    <button type="button" className="graph-chip-neutral" onClick={onRetry}>Check for updates</button>
  </div>;
}

export function FindingsGraphFreshnessNote({ freshness }: { freshness: GraphFreshness | null | undefined }) {
  if (freshness?.refresh_status !== "building") return null;
  const asOf = recordedAt(freshness.as_of);
  return <p role="status" className="rounded-lg border border-outline px-3 py-2 text-sm text-ink-secondary">
    Updating graph · reachability is unassessed until it is ready{asOf ? ` (last complete graph: data from ${asOf})` : ""}
  </p>;
}
