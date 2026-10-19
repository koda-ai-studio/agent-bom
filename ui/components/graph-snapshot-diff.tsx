"use client";

import type { DiffChangeCounts } from "@/lib/graph-utils";
import type { GraphDiffNode, GraphDiffResponse } from "@/lib/api-types";

/** The detailed two-snapshot diff: exact counts plus the first changed nodes of each kind. */
export function GraphSnapshotDiff({
  diff,
  counts,
  loading,
  error,
  showCounts = true,
}: {
  diff: GraphDiffResponse | null;
  counts: DiffChangeCounts;
  loading: boolean;
  error: string | null;
  /** Off where the caller already shows this pair's counts. */
  showCounts?: boolean;
}) {
  if (error) return <div className="graph-callout-amber">{error}</div>;
  if (loading && !diff) {
    return <div data-testid="graph-diff-loading" aria-label="Loading diff" className="mt-2 h-16 animate-pulse rounded-lg bg-surface-elevated" />;
  }
  if (!diff) return null;
  const lists = [
    { label: "Added", items: diff.nodes_added },
    { label: "Changed", items: diff.nodes_changed },
    { label: "Removed", items: diff.nodes_removed },
  ].filter(list => list.items.length > 0);
  return (
    <div data-testid="graph-snapshot-diff" className="mt-2 space-y-2">
      {showCounts && <p className="font-mono text-xs tabular-nums text-ink-secondary">
        <span className="text-emerald-700 dark:text-emerald-300">+{counts.nodesAdded}</span>{" "}
        <span className="text-amber-700 dark:text-amber-300">−{counts.nodesRemoved}</span> nodes ·{" "}
        <span className="text-sky-700 dark:text-sky-300">{counts.nodesChanged} changed</span> ·{" "}
        <span className="text-emerald-700 dark:text-emerald-300">+{counts.edgesAdded}</span>{" "}
        <span className="text-amber-700 dark:text-amber-300">−{counts.edgesRemoved}</span> links
      </p>}
      {counts.truncated && <p className="text-[11px] text-ink-tertiary">Lists show the first changes only; counts are exact.</p>}
      {lists.length > 0 && (
        <div className="grid gap-2">
          {lists.map(list => <DiffPreview key={list.label} label={list.label} items={list.items} />)}
        </div>
      )}
    </div>
  );
}

type DiffPreviewItem = GraphDiffNode | string;

function diffItemKey(item: DiffPreviewItem): string {
  return typeof item === "string" ? item : item.id;
}

function diffItemLabel(item: DiffPreviewItem): string {
  if (typeof item === "string") return item;
  return item.label || item.id;
}

export function DiffPreview({
  label,
  items,
}: {
  label: string;
  items: DiffPreviewItem[];
}) {
  const visible = items.slice(0, 5);
  return (
    <div className="rounded-xl border border-outline bg-surface/70 p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] uppercase tracking-[0.18em] text-ink-tertiary">
          {label}
        </p>
        <span className="font-mono text-[11px] text-ink-tertiary">
          {items.length}
        </span>
      </div>
      <div className="mt-2 space-y-1">
        {visible.map((item) => (
          <p
            key={`${label}-${diffItemKey(item)}`}
            className="truncate font-mono text-[11px] text-ink-secondary"
          >
            {diffItemLabel(item)}
          </p>
        ))}
        {items.length > visible.length && (
          <p className="text-[11px] text-ink-tertiary">
            +{items.length - visible.length} more
          </p>
        )}
      </div>
    </div>
  );
}
