import type { GraphDiffChangeCounts, GraphDiffResponse, GraphEstateChangesResponse } from "@/lib/api-types";
import type { DiffChangeCounts } from "@/lib/graph-utils";

export interface SnapshotPair {
  oldScanId: string;
  newScanId: string;
}

/** Sources whose full diffs feed the drift lens; bounded so one click never fans out unboundedly. */
export const HIGHLIGHT_SOURCE_LIMIT = 10;

const plural = (count: number, noun: string) => `${count.toLocaleString()} ${noun}${count === 1 ? "" : "s"}`;

export function countsLine(nodes: GraphDiffChangeCounts, edges: GraphDiffChangeCounts): string {
  return `+${nodes.added.toLocaleString()} −${nodes.removed.toLocaleString()} nodes · +${edges.added.toLocaleString()} −${edges.removed.toLocaleString()} links`;
}

/** One status-bar line; null when the tenant has no scan history to compare. */
export function estateChangesHeadline(changes: GraphEstateChangesResponse | null): string | null {
  if (!changes) return null;
  const { totals, pagination } = changes;
  if (!changes.sources.length && !changes.new_sources.length) return null;
  const bounded = pagination.has_more ? ` · first ${pagination.returned.toLocaleString()} of ${plural(pagination.total, "source")}` : "";
  if (!totals.changed_sources) {
    if (!changes.sources.length) return `First observation${bounded}`;
    return `No changes since previous scans${bounded}`;
  }
  const first = totals.new_sources ? ` · ${plural(totals.new_sources, "first observation")}` : "";
  return `${countsLine(totals.nodes, totals.edges)} · ${plural(totals.changed_sources, "source")}${first}${bounded}`;
}

/** A historical snapshot compares with the one before it, loaded only on request. */
export function snapshotChangesHeadline(counts: DiffChangeCounts | null, hasPrevious: boolean): string | null {
  if (!hasPrevious) return null;
  if (!counts) return "Compare with previous snapshot";
  const total = counts.nodesAdded + counts.nodesRemoved + counts.nodesChanged + counts.edgesAdded + counts.edgesRemoved;
  if (!total) return "No changes since previous snapshot";
  return countsLine(
    { added: counts.nodesAdded, removed: counts.nodesRemoved, changed: counts.nodesChanged },
    { added: counts.edgesAdded, removed: counts.edgesRemoved, changed: 0 },
  );
}

export function highlightPairs(changes: GraphEstateChangesResponse, limit = HIGHLIGHT_SOURCE_LIMIT): SnapshotPair[] {
  return changes.sources
    .filter(source => source.total_changes > 0)
    .slice(0, limit)
    .map(source => ({ oldScanId: source.old.scan_id, newScanId: source.new.scan_id }));
}

const addCounts = (a: GraphDiffChangeCounts, b: GraphDiffChangeCounts): GraphDiffChangeCounts => ({
  added: a.added + b.added,
  removed: a.removed + b.removed,
  changed: a.changed + b.changed,
});

/** Merge per-source full diffs into one drift-lens input; node ids are canonical across snapshots. */
export function mergeDriftDiffs(diffs: GraphDiffResponse[]): GraphDiffResponse {
  const zero = { added: 0, removed: 0, changed: 0 };
  const merged: GraphDiffResponse = {
    nodes_added: [], nodes_removed: [], nodes_changed: [], edges_added: [], edges_removed: [],
    change_kind_index: { nodes: {}, edges: {} },
    attribute_deltas: {},
    summary: { totals: { nodes: { ...zero }, edges: { ...zero } } },
    truncated: false,
  };
  for (const diff of diffs) {
    merged.nodes_added.push(...diff.nodes_added);
    merged.nodes_removed.push(...diff.nodes_removed);
    merged.nodes_changed.push(...diff.nodes_changed);
    merged.edges_added.push(...diff.edges_added);
    merged.edges_removed.push(...diff.edges_removed);
    Object.assign(merged.change_kind_index!.nodes, diff.change_kind_index?.nodes ?? {});
    Object.assign(merged.change_kind_index!.edges, diff.change_kind_index?.edges ?? {});
    Object.assign(merged.attribute_deltas!, diff.attribute_deltas ?? {});
    const totals = diff.summary?.totals;
    if (totals) {
      merged.summary!.totals.nodes = addCounts(merged.summary!.totals.nodes, totals.nodes);
      merged.summary!.totals.edges = addCounts(merged.summary!.totals.edges, totals.edges);
    }
    merged.truncated = merged.truncated || Boolean(diff.truncated);
  }
  return merged;
}
