"use client";

import type { GraphCollectionCoverage } from "@/lib/api-contracts/scan-inventory";
import { recordedAt } from "@/lib/graph-freshness";

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
