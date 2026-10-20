"use client";

import Link from "next/link";
import { useState } from "react";

import { changedNodeHref, type SnapshotPair } from "@/lib/graph-estate-changes";
import type { DiffChangeCounts } from "@/lib/graph-utils";
import type { GraphDiffNode, GraphDiffResponse } from "@/lib/api-types";

/** The detailed two-snapshot diff: exact counts plus the first changed nodes of each kind. */
export function GraphSnapshotDiff({
  diff,
  counts,
  loading,
  error,
  showCounts = true,
  pair = null,
}: {
  diff: GraphDiffResponse | null;
  counts: DiffChangeCounts;
  loading: boolean;
  error: string | null;
  /** Off where the caller already shows this pair's counts. */
  showCounts?: boolean;
  /** The compared snapshots: added and changed nodes open in the new one, removed nodes in the old one. */
  pair?: SnapshotPair | null | undefined;
}) {
  if (error) return <div className="graph-callout-amber">{error}</div>;
  if (loading && !diff) {
    return <div data-testid="graph-diff-loading" aria-label="Loading diff" className="mt-2 h-16 animate-pulse rounded-lg bg-surface-elevated" />;
  }
  if (!diff) return null;
  const lists = [
    { label: "Added", items: diff.nodes_added, total: counts.nodesAdded, scanId: pair?.newScanId },
    { label: "Changed", items: diff.nodes_changed, total: counts.nodesChanged, scanId: pair?.newScanId },
    { label: "Removed", items: diff.nodes_removed, total: counts.nodesRemoved, scanId: pair?.oldScanId },
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
        <div className="grid min-w-0 gap-2">
          {lists.map(list => <DiffPreview key={list.label} label={list.label} items={list.items} total={list.total} scanId={list.scanId} />)}
        </div>
      )}
    </div>
  );
}

type DiffPreviewItem = GraphDiffNode | string;

const PAGE = 10;
const KEEP_HEAD = 18;
const KEEP_TAIL = 30;

/** Long ids differ at the end (instance ids, versions), so keep the tail and elide the middle. */
export function middleTruncate(text: string, max = KEEP_HEAD + KEEP_TAIL + 1): string {
  return text.length <= max ? text : `${text.slice(0, KEEP_HEAD)}…${text.slice(-KEEP_TAIL)}`;
}

function diffItemKey(item: DiffPreviewItem): string {
  return typeof item === "string" ? item : item.id;
}

function diffItemLabel(item: DiffPreviewItem): string {
  if (typeof item === "string") return item;
  return item.label || item.id;
}

/**
 * One kind of change, a page at a time. Every entry links to its node in the
 * snapshot where it exists; long identifiers truncate with the full text as a
 * tooltip. `total` is the exact count when the server capped the list.
 */
export function DiffPreview({
  label,
  items,
  total,
  scanId,
}: {
  label: string;
  items: DiffPreviewItem[];
  total?: number | undefined;
  scanId?: string | undefined;
}) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(items.length / PAGE));
  const current = Math.min(page, pages - 1);
  const visible = items.slice(current * PAGE, current * PAGE + PAGE);
  const exact = total ?? items.length;
  const noun = `${label.toLowerCase()} nodes`;
  const range = `${(current * PAGE + 1).toLocaleString()}–${(current * PAGE + visible.length).toLocaleString()}`;
  return (
    <div className="min-w-0 rounded-xl border border-outline bg-surface/70 p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] uppercase tracking-[0.18em] text-ink-tertiary">{label}</p>
        <span className="font-mono text-[11px] tabular-nums text-ink-tertiary">{exact.toLocaleString()} nodes</span>
      </div>
      <ul aria-label={`${label} nodes`} className="mt-2 space-y-0.5">
        {visible.map((item) => {
          const text = diffItemLabel(item);
          return (
            <li key={`${label}-${diffItemKey(item)}`} className="min-w-0">
              <Link href={changedNodeHref(diffItemKey(item), text, scanId)} title={text}
                className="block truncate rounded px-1 py-0.5 font-mono text-[11px] text-ink-secondary hover:bg-surface-elevated hover:text-foreground">
                {middleTruncate(text)}
              </Link>
            </li>
          );
        })}
      </ul>
      {(pages > 1 || exact > items.length) && (
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-ink-tertiary">
          <span className="tabular-nums">
            {range} of {items.length.toLocaleString()}{exact !== items.length ? ` listed · ${exact.toLocaleString()} ${label.toLowerCase()}` : ""}
          </span>
          {pages > 1 && (
            <span className="flex items-center gap-1">
              <button type="button" aria-label={`Previous ${noun}`} disabled={current === 0} onClick={() => setPage(current - 1)}
                className="graph-page-action min-h-8 px-2 disabled:opacity-40">Previous</button>
              <button type="button" aria-label={`Next ${noun}`} disabled={current >= pages - 1} onClick={() => setPage(current + 1)}
                className="graph-page-action min-h-8 px-2 disabled:opacity-40">Next</button>
            </span>
          )}
        </div>
      )}
    </div>
  );
}
