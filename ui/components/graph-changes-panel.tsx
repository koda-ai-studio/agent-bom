"use client";

import type { ReactNode } from "react";
import { Loader2 } from "lucide-react";

import { Drawer } from "@/components/drawer";
import { GraphChangeAttribution } from "@/components/graph-change-attribution";
import { GraphChangeExposures } from "@/components/graph-change-exposures";
import { GraphChangeIssueBasis } from "@/components/graph-change-issue-basis";
import type { GraphEstateChangesResponse } from "@/lib/api-types";
import { countsLine, type SnapshotPair } from "@/lib/graph-estate-changes";

export interface GraphChangesPanelProps {
  open: boolean;
  /** Per-source estate changes; null when a historical snapshot is compared instead. */
  changes: GraphEstateChangesResponse | null;
  loading: boolean;
  error: string | null;
  highlighting: boolean;
  highlightLoading: boolean;
  /** Historical comparisons have no per-source list but can still arm the lens. */
  highlightAvailable?: boolean;
  highlightError?: string | null;
  selectedPair: SnapshotPair | null;
  /** Detailed diff for the selected pair (the existing snapshot diff). */
  diffDetails: ReactNode;
  title?: string;
  onClose: () => void;
  onHighlight: () => void;
  onOpenDiff: (pair: SnapshotPair, label: string) => void;
  /** Open a new finding or asset on the canvas. */
  onInvestigateNode?: ((id: string, label: string) => void) | undefined;
}

const when = (stamp: string) => {
  const parsed = new Date(stamp);
  return Number.isNaN(parsed.getTime()) ? "unknown time" : parsed.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};

const REASONS: Record<string, string> = {
  previous_graph_unavailable: "Some earlier snapshots have no graph; the nearest earlier graph was compared.",
  graph_evidence_unavailable: "A current scan has no graph yet; its earlier graph stays in the estate.",
  scan_history_unavailable: "Snapshots exist without scan history, so sources cannot be paired.",
  scan_partial: "A current scan was partial; removals may reflect incomplete collection.",
  snapshot_baseline: "A source scanned once is compared with the earlier retained snapshot no other source owns.",
};

function CompletenessNote({ changes }: { changes: GraphEstateChangesResponse }) {
  const notes = [
    changes.pagination.has_more
      ? `Showing ${changes.pagination.returned.toLocaleString()} of ${changes.pagination.total.toLocaleString()} sources; totals cover the sources shown.`
      : null,
    ...changes.completeness_reasons.map(reason => REASONS[reason] ?? `Coverage note: ${reason.replaceAll("_", " ")}.`),
  ].filter(Boolean);
  if (!notes.length) return null;
  return (
    <ul data-testid="graph-changes-completeness" className="space-y-1 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-100">
      {notes.map(note => <li key={note}>{note}</li>)}
    </ul>
  );
}

export function GraphChangesPanel({
  open,
  changes,
  loading,
  error,
  highlighting,
  highlightLoading,
  highlightAvailable = false,
  highlightError = null,
  selectedPair,
  diffDetails,
  title = "Changed since previous scans",
  onClose,
  onHighlight,
  onOpenDiff,
  onInvestigateNode,
}: GraphChangesPanelProps) {
  const changed = changes?.totals.changed_sources ?? 0;
  const canHighlight = changes ? changed > 0 : highlightAvailable;
  return (
    <Drawer
      open={open}
      onClose={onClose}
      size="md"
      eyebrow="What changed"
      title={title}
      subtitle={changes ? "Each source is compared with its previous comparable snapshot. Counts are graph nodes and links between the two snapshots, not finding occurrences." : undefined}
      ariaLabel={title}
      bodyClassName="space-y-3"
    >
      {(changes || highlightAvailable) && (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onHighlight}
            disabled={!canHighlight || highlightLoading}
            aria-pressed={highlighting}
            className="graph-page-action inline-flex items-center gap-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {highlightLoading && <Loader2 aria-hidden className="h-3.5 w-3.5 animate-spin" />}
            Highlight changes
          </button>
          {changes && (
            <span className="text-xs text-ink-tertiary">
              {changed ? `${changed.toLocaleString()} changed · ${changes.totals.unchanged_sources.toLocaleString()} unchanged` : "Nothing to highlight"}
            </span>
          )}
        </div>
      )}
      {highlightError && <p role="alert" className="text-xs text-amber-700 dark:text-amber-200">{highlightError}</p>}
      {loading && !changes && <p className="text-sm text-ink-secondary">Loading changes…</p>}
      {error && !changes && <p role="alert" className="text-sm text-amber-700 dark:text-amber-200">{error}</p>}
      {changes && <CompletenessNote changes={changes} />}
      {changes && changes.sources.length > 0 && (
        <section aria-label="Sources with a previous scan">
          <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.16em] text-ink-tertiary">Sources</h3>
          <ul className="divide-y divide-outline rounded-lg border border-outline">
            {changes.sources.map(source => {
              const pair = { oldScanId: source.old.scan_id, newScanId: source.new.scan_id };
              const selected = selectedPair?.oldScanId === pair.oldScanId && selectedPair.newScanId === pair.newScanId;
              return (
                <li key={source.scope_id} data-testid="graph-changes-source" aria-current={selected || undefined} className="space-y-1 px-3 py-2 aria-[current]:bg-surface-elevated">
                  <div className="flex items-start justify-between gap-2">
                    <p className="min-w-0 break-words text-sm font-medium text-foreground [overflow-wrap:anywhere]">{source.label}</p>
                    {source.total_changes > 0 && (
                      <button type="button" onClick={() => onOpenDiff(pair, source.label)} aria-label={`Open diff for ${source.label}`}
                        className="shrink-0 text-xs text-foreground underline underline-offset-4">
                        Open diff
                      </button>
                    )}
                  </div>
                  <p className="font-mono text-xs tabular-nums text-ink-secondary">
                    {source.total_changes > 0 ? countsLine(source.counts.nodes, source.counts.edges) : "No changes"}
                    {source.counts.nodes.changed > 0 && ` · ${source.counts.nodes.changed.toLocaleString()} nodes changed`}
                  </p>
                  <p className="text-xs text-ink-tertiary">
                    {when(source.old.captured_at)} → {when(source.new.captured_at)}
                    {source.skipped_snapshots > 0 && ` · ${source.skipped_snapshots} snapshot${source.skipped_snapshots === 1 ? "" : "s"} without graph skipped`}
                  </p>
                  {source.baseline === "snapshot_continuity" && (
                    <p className="text-xs text-ink-tertiary [overflow-wrap:anywhere]">Compared with earlier snapshot {source.old.scan_id}</p>
                  )}
                  <GraphChangeIssueBasis change={source.issue_change} />
                  <GraphChangeAttribution attribution={source.changes_by_source} />
                  <GraphChangeExposures highlights={source.highlights ?? {}} scanId={source.new.scan_id} previousScanId={source.old.scan_id}
                    onInvestigateNode={onInvestigateNode} onOpenDiff={() => onOpenDiff(pair, source.label)} />
                  {selected && diffDetails}
                </li>
              );
            })}
          </ul>
        </section>
      )}
      {changes && changes.new_sources.length > 0 && (
        <section aria-label="First observations">
          <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.16em] text-ink-tertiary">First observations</h3>
          <ul className="divide-y divide-outline rounded-lg border border-outline">
            {changes.new_sources.map(source => (
              <li key={source.scope_id} data-testid="graph-changes-first-observation" className="space-y-0.5 px-3 py-2">
                <p className="break-words text-sm font-medium text-foreground [overflow-wrap:anywhere]">{source.label}</p>
                <p className="text-xs text-ink-secondary">
                  {source.reason === "first_observation" ? "First observation" : "No earlier graph to compare"} · {source.node_count.toLocaleString()} nodes · {source.edge_count.toLocaleString()} links · not counted as additions
                </p>
                <p className="text-[11px] text-ink-tertiary">{when(source.new.captured_at)}</p>
              </li>
            ))}
          </ul>
        </section>
      )}
      {!changes && diffDetails}
    </Drawer>
  );
}
