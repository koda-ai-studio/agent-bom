"use client";

import dynamic from "next/dynamic";
import { useInvestigationFlowView } from "@/hooks/use-investigation-flow-view";
import { GraphAdvancedControls } from "@/components/graph-advanced-controls";
import { GraphAnalysisStatusBanner } from "@/components/graph-analysis-status";
import { BlastRadiusPanel } from "@/components/graph-blast-radius-panel";
import { GraphConnectionsList } from "@/components/graph-connections-list";
import { GraphFlowCanvas } from "@/components/graph-flow-canvas";
import { GraphFlowEdgeLegend } from "@/components/graph-flow-edge-legend";
import { GraphInViewHint } from "@/components/graph-in-view-hint";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { graphPageGate } from "@/components/graph-page-gate";
import { GraphPartialView } from "@/components/graph-partial-view";
import { GraphPathList } from "@/components/graph-path-list";
import { GraphProjectionNotice } from "@/components/graph-projection-notice";
import { GraphPulseStyles as PulseStyles } from "@/components/graph-pulse-styles";
import { GraphRollupChildPager } from "@/components/graph-rollup-child-pager";
import { GraphRollupCountNotice } from "@/components/graph-rollup-count-notice";
import { GraphScenarioPanel } from "@/components/graph-scenario-panel";
import { GraphScenarioUnconnected } from "@/components/graph-scenario-unconnected";
import { GraphScopeOverview } from "@/components/graph-scope-overview";
import { GraphSearchResults } from "@/components/graph-search-results";
import { GraphSelectionPanels } from "@/components/graph-selection-panels";
import { GraphScopeNavigation, GraphSearchForm, GraphSnapshotControls } from "@/components/graph-snapshot-controls";
import { GraphEmptyState, GraphFindingsFallback, GraphPanelSkeleton, GraphRefreshOverlay } from "@/components/graph-state-panels";
import { GraphChangesDialog, GraphPhoneFooter, GraphStatusBar } from "@/components/graph-status-bar";
import { GraphViewControls } from "@/components/graph-view-controls";
import { createExpandedGraphFilters, createInvestigationGraphFilters, graphScopeLabelForFilters } from "@/components/lineage-filter";
import { useRelationshipLabelControl } from "@/components/relationship-label-control";
import type { GraphPageData } from "@/hooks/use-graph-page-data";
import type { GraphCanvasModel } from "@/hooks/use-graph-canvas-model";
import type { GraphPageActions } from "@/hooks/use-graph-page-actions";

export type GraphPageModel = GraphPageData & GraphCanvasModel & GraphPageActions;

const GraphFocusedPathDecision = dynamic(() => import("@/components/graph-focused-path-decision").then(mod => mod.GraphFocusedPathDecision), { ssr: false });

const SigmaGraphOverview = dynamic(() => import("@/components/sigma-graph-overview").then(mod => mod.SigmaGraphOverview), {
  ssr: false,
  loading: () => <GraphPanelSkeleton title="Loading WebGL graph" detail="Preparing the Sigma renderer for the broad graph overview." />,
});

/** The graph page: header, view controls, status bar, canvas and detail drawers. */
export function GraphPageView({ page }: { page: GraphPageModel }) {
  const {
    narrowViewport, setGraphNavigationMount, session, authLoading, snapshotListUnavailable, setCanvasPage, selectedScanId, graphData, selectedScenarioId, selectedScenario,
    selectedRelationship, setSelectedNode, selectedNodeId, setSelectedNodeId, setSelectedRelationship, hoveredNodeId, pinnedFocusId, setPinnedFocusId, setHoveredNodeId,
    setSelectedAttackPathKey, requestedAttackPathKeyRef, selectedAttackPath, selectedPathDecision, graphNodeById, selectedEvidenceHopCount, activeSnapshot, captureMode,
    investigationMode, clearInvestigationMode, reachabilitySummary, setReachabilitySummary, reachabilityError, loadingReachability, blastRadius, setBlastRadius, loadingBlast, blastError, returnToSummary,
    searchResults, filters, setFilters, flow, validValues, focusSearchResult, rollupCanvasOwnsPresentation, restoreSummaryOnFilterReset, dismissRollup, handleResetFilters, rollupPreferenceRef, setRollupDismissed,
    selectContextGroup, presentation, setManualCameraScope, rollupNavigationActive, loadingRollup, rollupView, setRollupChildPage, rollupChildPageKey, mobileListActive, displayNodes, displayEdges, flowNodeById, onNodeClick,
    graphLayoutKind, rollupDecisionActive, scenarioElements, scenarioConnectionNotes, retryGraph, graphPanelError, loadingGraph, firstFramePending, rollupCanvasFailed, estateNodeCount, rollupCanvasPending,
    rollupItems, drillIntoRollup, investigateRollup, estateIssueSummary, layoutPending, graphRenderer, graphOnlyFindings, findingNodes, selectFindingCard, onLargeGraphNodeSelect, presentationScope,
    connectionPreview, previewExpanded, setPreviewExpanded, searchParams, contextElements, legendItems,
  } = page;
  const relationshipLabels = useRelationshipLabelControl(displayEdges);
  const clearSelection = () => {
    setSelectedNode(null);
    setSelectedNodeId(null);
    setSelectedRelationship(null);
    setPinnedFocusId(null);
    setHoveredNodeId(null);
    setReachabilitySummary(null);
    setBlastRadius(null);
  };
  const flowView = useInvestigationFlowView({
    presentation, edges: relationshipLabels.edges, loaded: contextElements, narrowViewport, requestedFlow: searchParams.get("flow"),
    otherSurface: Boolean(selectedAttackPath || selectedScenarioId || rollupNavigationActive),
    webglNodeCount: graphRenderer.kind === "webgl" ? displayNodes.length : null,
    connectionPreview, previewExpanded, setPreviewExpanded, selectedNodeId, focusNodeIds: [pinnedFocusId ?? hoveredNodeId, investigationMode?.rootId ?? null], selectedRelationshipId: selectedRelationship?.id ?? null,
    clearSelection, resetCamera: () => setManualCameraScope(null),
  });
  const { disclosed } = flowView;
  const gate = graphPageGate(page);
  if (gate) return gate;
  const webgl = graphRenderer.kind === "webgl";
  const frameHeight = rollupDecisionActive ? "min-h-[28rem]"
    : selectedAttackPath ? "h-[max(24rem,calc(100dvh-25rem))] sm:h-[clamp(24rem,50dvh,36rem)]"
      : selectedScenarioId ? "h-[max(24rem,calc(100dvh-25rem))] sm:h-[max(28rem,calc(100dvh-21rem))]"
        : webgl ? "max-sm:h-auto sm:h-[max(30rem,calc(100dvh-15rem))]"
          : "h-[var(--graph-adaptive-height,clamp(22rem,60dvh,48rem))]";

  return (
    // min-h instead of h so the page can grow taller than the viewport
    // when the snapshot diff cards / how-to-read prose / findings
    // fallback panel push content past the fold. Previously the fixed
    // h-[calc(100vh-3.5rem)] container clipped everything below the
    // viewport, leaving users stuck on the snapshot row with no way
    // to scroll to the React Flow canvas or the findings panel.
    <div className="min-h-[calc(100vh-3.5rem)] flex flex-col">
      <PulseStyles />
          {snapshotListUnavailable && <p role="status" className="text-sm text-ink-secondary">Snapshot list unavailable. The selected graph can still be explored.</p>}


      <div className="graph-page-header">
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
          <h1 className="shrink-0 text-lg font-semibold text-foreground max-sm:sr-only sm:mt-1">Investigation</h1>
          <GraphLensSwitcher variant="compact" scanId={selectedScanId || undefined} />
          <div className="hidden sm:block">
            {!investigationMode && <GraphAnalysisStatusBanner
              status={graphData?.stats.analysis_status?.attack_path_fusion}
              compact
            />}
          </div>
        </div>

        <div className="sm:mt-3">
          {narrowViewport && <GraphScopeNavigation page={page} />}

          <GraphSearchResults results={searchResults} severity={filters.severity} onSelect={result => void focusSearchResult(result)} />

          {investigationMode && !reachabilitySummary && !blastRadius && !loadingBlast && (
            <div className="flex flex-wrap items-center gap-3 py-2 text-xs text-ink-secondary">
              <span>
                Focused on:{" "}
                <span className="font-mono">{investigationMode.rootLabel || investigationMode.rootId}</span>
                {investigationMode.truncated
                  ? " · traversal budget reached"
                  : ""}
              </span>
              <button
                type="button"
                onClick={clearInvestigationMode}
                className="rounded-lg border border-sky-400/30 bg-sky-950/60 px-2.5 py-1 text-sky-100 transition hover:border-sky-300"
              >
                Clear focus
              </button>
            </div>
          )}

          {reachabilityError && <p role="alert" className="py-2 text-sm text-amber-700 dark:text-amber-200">{reachabilityError}</p>}
          {loadingReachability && <p role="status" className="py-2 text-sm text-ink-secondary">Loading connections…</p>}

          {(blastRadius || loadingBlast || blastError) && (
            <BlastRadiusPanel
              summary={blastRadius}
              loading={loadingBlast}
              error={blastError}
              onClear={returnToSummary}
            />
          )}

          <div className="relative sm:mt-1">
          <GraphViewControls
            actions={!narrowViewport ? <div className="order-first flex min-w-0 flex-1 flex-wrap items-center gap-2"><GraphScopeNavigation page={page} /><GraphSnapshotControls page={page} /><details className="relative ml-auto">
              <summary className="graph-page-action cursor-pointer">Search graph</summary>
              <div className="absolute right-0 top-full z-30 mt-2 w-96 max-w-[calc(100vw-4rem)] rounded-xl border border-outline bg-surface p-3 shadow-lg"><GraphSearchForm page={page} /></div>
            </details></div> : <>
              <details data-testid="mobile-graph-view">
                <summary className="graph-page-action graph-action-compact min-h-[38px] cursor-pointer">Snapshot &amp; view</summary>
                <div className="absolute inset-x-0 top-full z-30 mt-1 flex flex-wrap gap-2 rounded-xl border border-outline bg-surface p-3 shadow-lg"><GraphSnapshotControls page={page} /></div>
              </details>
              <details className="ml-auto" data-testid="mobile-graph-search">
                <summary className="graph-page-action graph-action-compact min-h-[38px] cursor-pointer">Search graph</summary>
                <div className="absolute inset-x-0 top-full z-30 mt-1 rounded-xl border border-outline bg-surface p-3 shadow-lg"><GraphSearchForm page={page} /></div>
              </details>
            </>}
            filters={filters}
            onChange={(next) => {
              if (rollupCanvasOwnsPresentation) restoreSummaryOnFilterReset.current = true;
              requestedAttackPathKeyRef.current = null;
              setSelectedAttackPathKey(null);
              dismissRollup();
              setFilters(next);
            }}
            agentNames={flow.agentNames}
            validValues={validValues}
            estateSummary={rollupCanvasOwnsPresentation}
            focusedPath={Boolean(selectedAttackPath)}
            onReset={() => {
              disclosed.reset();
              flowView.setAllEdgesShown(false);
              if (flowView.kind !== "auto") flowView.selectFlow("auto");
              if (investigationMode) {
                // Same root, investigation defaults: depth 1, every layer and relationship, a fresh fit.
                setFilters(current => createInvestigationGraphFilters(current));
                selectContextGroup("all");
                setCanvasPage(0);
                presentation.reset();
                setManualCameraScope(null);
                return;
              }
              handleResetFilters();
              if (restoreSummaryOnFilterReset.current) {
                rollupPreferenceRef.current = "force";
                setRollupDismissed(false);
                restoreSummaryOnFilterReset.current = false;
              }
            }}
          >
            <GraphAdvancedControls page={page} />
          </GraphViewControls>
          </div>
        </div>
      </div>

      {/* Reserve the remaining viewport for topology; expanded evidence and
          focused-path content can still scroll without hiding the controls. */}
      <div
        data-testid={selectedAttackPath ? "focused-path-surface" : undefined}
        className={selectedScenario
          ? "relative grid gap-4 px-4 py-3 lg:grid-cols-[minmax(0,1fr)_320px] lg:h-[max(28rem,calc(100dvh-18rem))]"
          : selectedAttackPath
            ? "flex relative min-h-[540px]"
            : "flex relative min-h-0"}
      >
        <div className={`flex-1 relative min-w-0 flex flex-col ${selectedScenario ? "min-h-[26rem] lg:min-h-0" : "min-h-0"}`} data-testid="investigation-graph-workspace">
          {selectedAttackPath && selectedPathDecision && <GraphFocusedPathDecision path={selectedAttackPath} decision={selectedPathDecision} nodeById={graphNodeById}
            evidenceHopCount={selectedEvidenceHopCount} snapshotCreatedAt={activeSnapshot?.created_at ?? null} captureMode={captureMode}
            onReturn={() => { requestedAttackPathKeyRef.current = null; setSelectedAttackPathKey(null); }} />}
          {rollupNavigationActive && !loadingRollup && <GraphRollupCountNotice metadata={rollupView?.aggregate_count_metadata} />}
          {rollupNavigationActive && !loadingRollup && (rollupView?.mode === "drilldown" || rollupView?.mode === "rollup") && (
            <GraphRollupChildPager
              pagination={rollupView.pagination}
              scope={rollupView.mode === "rollup" ? "top_level" : "children"}
              onPage={(offset) => setRollupChildPage({ key: rollupChildPageKey, offset, generation: rollupView?.snapshot_generation })}
            />
          )}
          <GraphStatusBar page={page} flowView={flowView} relationshipLabels={relationshipLabels} />
          <GraphChangesDialog page={page} />
          {mobileListActive && (investigationMode
            ? <GraphConnectionsList rootId={investigationMode.rootId} nodes={displayNodes} edges={relationshipLabels.edges} memberNodes={flowNodeById}
              onSelect={id => { const node = flowNodeById.get(id); if (node) onNodeClick({} as React.MouseEvent, node); }} />
            : <GraphPathList nodes={displayNodes} edges={relationshipLabels.edges}
              onSelect={id => { const node = flowNodeById.get(id) ?? displayNodes.find(item => item.id === id); if (node) onNodeClick({} as React.MouseEvent, node); }} />)}
          <div data-graph-adaptive-frame data-graph-annotations={graphLayoutKind === "asset-hierarchy" ? "on-demand" : undefined} className={`${mobileListActive ? "hidden " : ""}relative flex ${frameHeight} shrink-0 overflow-hidden rounded-lg border border-outline bg-surface`}>
          <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <GraphScenarioUnconnected
            nodes={scenarioElements.unconnected}
            notes={scenarioConnectionNotes}
            selectedId={selectedNodeId}
            onSelect={node => onNodeClick({} as React.MouseEvent, node)}
          />
          {!captureMode && !webgl && <GraphInViewHint edges={{ drawn: flowView.quieted.drawn, total: flowView.quieted.total, held: flowView.quieted.held, allShown: flowView.allEdgesShown, onToggle: flowView.setAllEdgesShown }} />}
          <div className={`relative min-h-0 min-w-0 flex-1 ${webgl ? "flex flex-col" : ""}`}>
          <GraphProjectionNotice coverage={(rollupCanvasOwnsPresentation ? rollupView : graphData)?.collection_coverage} onRetry={retryGraph} />
          {graphPanelError && graphData && !loadingGraph && (
            <div role="status" className="flex items-center justify-between gap-3 border-b border-outline px-4 py-2 text-sm">
              <span>Refresh failed. Showing the last loaded graph for this scope.</span>
              <button type="button" className="graph-chip-neutral" onClick={retryGraph}>Retry graph</button>
            </div>
          )}
          {((loadingGraph || loadingBlast) && !graphData) || firstFramePending ? (
            <GraphPanelSkeleton
              title="Loading graph window"
              detail={`Fetching the selected snapshot with the ${graphScopeLabelForFilters(filters).toLowerCase()} scope and active layer filters.`}
            />
          ) : graphPanelError && !graphData ? (
            <GraphEmptyState
              title={graphPanelError.title}
              detail={graphPanelError.detail}
              suggestions={graphPanelError.suggestions}
              actions={[{ label: "Retry graph", onClick: retryGraph }, { label: "Return to summary", onClick: returnToSummary }]}
            />
          ) : rollupCanvasFailed ? (
            <GraphEmptyState
              title="Scope navigation did not load"
              detail={`The ${estateNodeCount.toLocaleString()}-node snapshot is not drawn as a raw map by default. Retry the scope summary, or open the bounded map of ranked assets.`}
              suggestions={["Search for an asset to investigate it directly", "Filter by severity to narrow the scope"]}
              actions={[{ label: "Retry scope", onClick: retryGraph }, { label: "Open bounded map", onClick: dismissRollup }]}
            />
          ) : rollupCanvasPending ? (
            <GraphPanelSkeleton
              title="Loading scope navigation"
              detail="Grouping the containment hierarchy."
            />
          ) : rollupDecisionActive ? (
            <GraphScopeOverview
              items={rollupItems}
              edges={rollupView?.edges ?? []}
              completeness={rollupView?.completeness}
              edgeCountMetadata={rollupView?.edge_count_metadata}
              onDrill={drillIntoRollup}
              onInvestigate={investigateRollup}
              estateIssueCount={estateIssueSummary?.issue_count}
              estateIssueBasis={estateIssueSummary}
            />
          ) : displayNodes.length === 0 && scenarioElements.unconnected.length > 0 ? (
            <div className="flex h-full items-center justify-center p-6 text-sm text-ink-secondary">No connected nodes in this proposal view. Select an unconnected item to inspect its details.</div>
          ) : displayNodes.length === 0 ? (
            <GraphEmptyState
              inventoryEmpty={estateNodeCount === 0 && !investigationMode && !selectedScenarioId}
              title="No nodes match the current graph scope"
              detail={investigationMode && investigationMode.nodeCount > 0 ? `${investigationMode.nodeCount} nodes were returned, but the active display filters hide them. This does not establish an absence of risk.` : "No results for these layers, severity and scope."}
              suggestions={[
                "Lower severity or disable vulnerable-only.",
                "Use Expanded for broader topology.",
                "Enable package and server layers.",
              ]}
              actions={[{ label: "Show all returned context", onClick: () => setFilters(createExpandedGraphFilters()) }, { label: "Return to summary", onClick: returnToSummary }]}
            />
          ) : layoutPending && !investigationMode && graphRenderer.kind === "react-flow" ? (
            <p role="status" className="p-6 text-sm text-ink-secondary">Arranging the selected graph…</p>
          ) : graphOnlyFindings ? (
            <GraphFindingsFallback
              nodes={findingNodes}
              onSelect={selectFindingCard}
              scanId={selectedScanId || undefined}
              onExpandScope={() =>
                setFilters(
                  createExpandedGraphFilters(
                    filters.agentName ?? flow.agentNames[0] ?? null,
                  ),
                )
              }
            />
          ) : graphRenderer.kind === "webgl" ? (
            <div className="min-h-0 flex-1 max-sm:flex-none">
            <SigmaGraphOverview
              embedded
              nodes={displayNodes}
              edges={relationshipLabels.edges}
              legendItems={legendItems}
              onNodeSelect={onLargeGraphNodeSelect}
              selectedId={selectedNodeId}
              onClearSelection={() => {
                setSelectedNode(null);
                setSelectedNodeId(null);
                setPinnedFocusId(null);
                setHoveredNodeId(null);
              }}
              presentationScope={presentationScope}
              presentationEnabled={!authLoading && Boolean(session)}
            />
            </div>
          ) : (
            <GraphFlowCanvas page={page} flowView={flowView} />
          )}

          {(loadingGraph || loadingBlast) && graphData && <GraphRefreshOverlay label={loadingBlast ? "Computing blast radius · current view retained" : "Loading related assets · current view retained"} />}

          <GraphPartialView page={page} />
          </div>
          </div>
          <GraphSelectionPanels page={page} flowView={flowView} />
          </div>
          {/* Under the canvas, so a phone's graph can start near the top of the screen. */}
          {graphRenderer.kind === "react-flow" && !mobileListActive && displayNodes.length > 0 && <GraphFlowEdgeLegend edges={flowView.quieted.edges} />}
          <div ref={setGraphNavigationMount} className={mobileListActive ? "hidden" : "mt-1"} />
          <GraphPhoneFooter page={page} flowView={flowView} />
        </div>
        {selectedScenario && (
          <aside aria-label="Scenario decision" className="min-w-0 lg:min-h-0 lg:overflow-y-auto">
            <GraphScenarioPanel page={page} />
          </aside>
        )}
      </div>
    </div>
  );
}
