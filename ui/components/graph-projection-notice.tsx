"use client";

import type { GraphCollectionCoverage } from "@/lib/api-contracts/scan-inventory";

export function GraphProjectionNotice({ coverage, onRetry }: {
  coverage?: GraphCollectionCoverage | undefined;
  onRetry: () => void;
}) {
  if (coverage?.refresh_status !== "building") return null;
  return <div role="status" className="flex flex-wrap items-center justify-between gap-2 border-b border-outline px-4 py-2 text-sm text-ink-secondary">
    <span>Updating graph · showing the previous complete view</span>
    <button type="button" className="graph-chip-neutral" onClick={onRetry}>Check for updates</button>
  </div>;
}
