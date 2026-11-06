"use client";

import { LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES } from "@/lib/large-graph-overview";
import type { GraphPageModel } from "@/components/graph-page-view";

/** Says what the bounded canvas left out, and offers the way to reach it. */
export function GraphPartialView({ page }: { page: GraphPageModel }) {
  const { layoutInput, setCanvasPage, graphTruncated, rollupCanvasOwnsPresentation, graphData, mergedGraphData, activeSnapshot, investigationMode, graphFetchLimit, returnToSummary, loadingGraph, setExpandedGraphScanId, selectedScanId } = page;
  // Path hops merge into the map, so the count here must match the one the map itself reports.
  const loaded = mergedGraphData?.nodes.length ?? graphData?.nodes.length ?? 0;
  return <>
          {layoutInput.omittedNodes > 0 && <div role="group" aria-label="Canvas context pages" className="mt-2 flex flex-wrap items-center gap-2 border-t border-outline pt-2 text-xs text-ink-secondary">
            <p role="status">{layoutInput.nodes.length} nodes on canvas · {layoutInput.omittedNodes} loaded nodes bundled off canvas.</p>
            <button type="button" disabled={layoutInput.page === 0} className="graph-page-action disabled:opacity-50" onClick={() => setCanvasPage(layoutInput.page - 1)}>Previous context</button>
            <button type="button" disabled={layoutInput.page + 1 >= layoutInput.pageCount} className="graph-page-action disabled:opacity-50" onClick={() => setCanvasPage(layoutInput.page + 1)}>Expand next context bundle</button>
          </div>}
          {graphTruncated && !rollupCanvasOwnsPresentation && (
            <details className="mt-2 border-t border-outline pt-2 text-xs text-ink-secondary" data-testid="graph-partial-view">
              <summary className="cursor-pointer">
                Partial view · {loaded.toLocaleString()} nodes loaded
                {graphData?.completeness?.edges_truncated && " · relationships limited"}
                {activeSnapshot && activeSnapshot.node_count > loaded
                  ? ` · ${activeSnapshot.node_count.toLocaleString()} in snapshot`
                  : activeSnapshot ? null : " · snapshot total unavailable"}
              </summary>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <p className="min-w-0 flex-1">
                  {investigationMode ? "This investigation reached a traversal limit." : `This selection requests up to ${graphFetchLimit.toLocaleString()} ranked assets plus supporting ancestors.`} Filters, traversal and rendering limits can exclude context. Search and scope summaries cover the snapshot independently.
                </p>
                {graphData?.completeness?.edges_truncated && <p>Some relationships are omitted from this overview. Select a node to investigate and page its recorded connections.</p>}
                <button type="button" onClick={returnToSummary} className="graph-chip-neutral">Browse scopes</button>
                {!investigationMode && (!graphData?.completeness?.edges_truncated || graphData?.pagination?.has_more) && graphFetchLimit < LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES && (
                  <button type="button" disabled={loadingGraph} onClick={() => setExpandedGraphScanId(selectedScanId)} className="graph-chip-neutral">
                    Load broader map (up to {LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES.toLocaleString()} ranked assets)
                  </button>
                )}
              </div>
            </details>
          )}
  </>;
}
