"use client";

import type { GraphFreshness } from "@/lib/api-contracts/findings";
import { recordedAt } from "@/lib/graph-freshness";

export function FindingsGraphFreshnessNote({ freshness }: { freshness: GraphFreshness | null | undefined }) {
  if (freshness?.refresh_status !== "building") return null;
  const asOf = recordedAt(freshness.as_of);
  return <p role="status" className="rounded-lg border border-outline px-3 py-2 text-sm text-ink-secondary">
    Updating graph · reachability is unassessed until it is ready{asOf ? ` (last complete graph: data from ${asOf})` : ""}
  </p>;
}
