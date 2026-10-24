"use client";

import { GraphFocusedPathDecision } from "@/components/graph-focused-path-decision";
import { AlertTriangle } from "lucide-react";
import { GraphConnectionsList } from "@/components/graph-connections-list";
import { GraphPathList } from "@/components/graph-path-list";
import { ScopeBreadcrumbChip } from "@/components/graph-scope-breadcrumb";
import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";
import { GraphScopeEvidence } from "@/components/graph-scope-evidence";
import { GraphInvestigationContextControls } from "@/components/graph-investigation-context-controls";
import { GraphCanvasAutoFit } from "@/components/graph-canvas-auto-fit";
import { GraphSnapshotReceipt } from "@/components/graph-snapshot-receipt";
import { relationshipEdgeTypes } from "@/components/relationship-edge";
import { GraphRollupChildPager } from "@/components/graph-rollup-child-pager";
import { GraphRollupCountNotice } from "@/components/graph-rollup-count-notice";
import dynamic from "next/dynamic";
import { Background, Controls, MiniMap, ReactFlow } from "@xyflow/react";
import { Loader2, ShieldAlert } from "lucide-react";
import { GraphEvidenceSummary } from "@/components/graph-evidence-summary";
import { formatGraphHeadline } from "@/lib/graph-headline";
import { GraphAnalysisStatusBanner } from "@/components/graph-analysis-status";
import { GraphEvidenceExportButton, FullscreenButton, GraphInteractionToolbar, GraphLegendDock } from "@/components/graph-chrome";
import { GraphDriftTimeline } from "@/components/graph-drift-timeline";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";
import { GraphScenarioAuthoring, GraphScenarioComparisonPanel, GraphScenarioSelector } from "@/components/graph-scenario-comparison";
import { GraphRelationshipDetail, GraphRollupRelationshipDetail } from "@/components/graph-relationship-detail";
import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import { GraphRollupDecisionSurface } from "@/components/graph-rollup-decision-surface";
import { GraphEmptyState, GraphFindingsFallback, GraphPanelSkeleton, GraphRefreshOverlay } from "@/components/graph-state-panels";
import { GraphViewControls } from "@/components/graph-view-controls";
import { createExpandedGraphFilters, createInvestigationGraphFilters, graphScopeLabelForFilters } from "@/components/lineage-filter";
import { lineageNodeTypesAdaptive } from "@/components/lineage-nodes";
import { readableGraphNodeStyle } from "@/lib/graph-node-dimensions";
import { BACKGROUND_COLOR, BACKGROUND_GAP, CONTROLS_CLASS, MINIMAP_BG, MINIMAP_CLASS, MINIMAP_MASK, minimapNodeColor } from "@/lib/graph-utils";
import { BlastRadiusPanel } from "@/components/graph-blast-radius-panel";
import { LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES } from "@/lib/large-graph-overview";
import { shouldVirtualizeReactFlowNodes } from "@/lib/graph-renderer-switch";
import { GraphScenarioUnconnected } from "@/components/graph-scenario-unconnected";
import { roleCanConnect } from "@/lib/roles";
import { GraphChangesEntry } from "@/components/graph-changes-entry";
import { GraphChangesPanel } from "@/components/graph-changes-panel";
import { GraphSearchResults } from "@/components/graph-search-results";
import { GraphSnapshotDiff } from "@/components/graph-snapshot-diff";
import { snapshotChangesHeadline } from "@/lib/graph-estate-changes";
import { snapshotLabel, snapshotOptionLabel } from "@/lib/snapshot-label";
import { estateIssueLine } from "@/lib/graph-issue-labels";
import { GraphPulseStyles as PulseStyles } from "@/components/graph-pulse-styles";
import { RollupNavigationPanel } from "@/components/graph-rollup-navigation-panel";
import { GraphOperatorTools } from "@/components/graph-operator-tools";
import { GraphAttackPathQueue } from "@/components/graph-attack-path-queue";
import type { GraphPageData } from "@/hooks/use-graph-page-data";
import type { GraphCanvasModel } from "@/hooks/use-graph-canvas-model";
import type { GraphPageActions } from "@/hooks/use-graph-page-actions";

const SigmaGraphOverview = dynamic(() => import("@/components/sigma-graph-overview").then(mod => mod.SigmaGraphOverview), {
  ssr: false,
  loading: () => <GraphPanelSkeleton title="Loading WebGL graph" detail="Preparing the Sigma renderer for the broad graph overview." />,
});

/** The graph page: header, view controls, status bar, canvas and detail drawers. */
export function GraphPageView({ page }: { page: GraphPageData & GraphCanvasModel & GraphPageActions }) {
  const {
    nodesInitialized, graphViewport, narrowViewport, setCanvasLayoutAspect, graphNavigationMount,
    setGraphNavigationMount, session, authLoading, setSnapshotRetry, snapshotListUnavailable, setCanvasPage,
    setExpandedGraphScanId, minimapExpanded, setMinimapExpanded, snapshots, selectedScanId, setSelectedScanId,
    currentEstateId, graphFetchLimit, graphData, scenarios, setScenarios, selectedScenarioId, setSelectedScenarioId,
    setExpandedScenarioId, scenarioExpanded, scenarioState, setScenarioState, scenarioComparison,
    setScenarioComparison, loadingScenarios, loadingScenarioComparison, scenarioError, setScenarioError,
    setScenarioRefreshKey, loadingSnapshots, loadingGraph, loadingDiff, error, rateLimited, diffError,
    setComparisonRequested, selectedNodeDetail, graphDiff, edgeChanges, loadingEdgeChanges, edgeChangesError,
    historySnapshots, loadingHistory, driftScrubberPair, setDriftScrubberPair, driftLensActive, setDriftLensActive,
    driftFilter, setDriftFilter, changesOpen, setChangesOpen, evidenceLensActive, setEvidenceLensActive,
    evidenceFilter, setEvidenceFilter, selectedNode, setSelectedNode, selectedNodeId, setSelectedNodeId,
    selectedRelationship, setSelectedRelationship, setSelectedAttackPathKey, requestedAttackPathKeyRef, searchQuery,
    setSearchQuery, searchResults, searching, investigationMode, reachabilitySummary, setReachabilitySummary,
    loadingReachability, mobileGraphView, setMobileGraphView, investigationDirection, reachabilityError,
    setReachabilityError, blastRadius, setBlastRadius, loadingBlast, blastError, setBlastError, rollupView,
    rollupStack, setRollupStack, rollupAutoDescendRef, rollupDismissed, setRollupDismissed, loadingRollup,
    setRollupChildPage, rollupError, rollupUnavailable, setRollupMapExpanded, restoreSummaryOnFilterReset,
    setHoveredNodeId, setPinnedFocusId, filters, setFilters, rollupPreferenceRef, canvasLens, selectedScenario,
    attackPathLens, captureMode, mergedGraphData, activeSnapshot, previousSnapshot, diffPair, viewingCurrentEstate,
    graphChanges, highlight, graphNodeById, activeScopePreset, attackPaths, effectiveSelectedAttackPathKey,
    selectedAttackPath, estateNodeCount, rollupEligible, rollupNavigationActive, rollupCanvasPending,
    rollupCanvasFailed, rollupCanvasOwnsPresentation, rollupItems, rollupDecisionAvailable, rollupDecisionActive,
    rollupChildPageKey, estateIssueSummary, rollupDisplayEdges, flow, snapshotAttackPathCount, firstFramePending,
    validValues, handleResetFilters, flowNodeById, graphLayoutKind, rootConnections, scenarioContextIds,
    scenarioConnectionNotes, scenarioElements, investigationContext, compactInvestigationTopology,
    selectedContextGroup, contextElements, selectContextGroup, layoutInput, layoutPending, selectedEvidenceHopCount,
    selectedVisibleHopCount, selectedPathDecision, lensDiff, driftIndex, diffCounts, driftAttributeSummaryList,
    driftLensEngaged, displayNodes, drift, evidenceCounts, compressedGroupCount, displayEdges, legendItems,
    viewportOptions, setManualCameraScope, manualCamera, initialViewportOptions, showMiniMap, presentationScope,
    presentation, fitGeneration, fitVisible, fitSelection, compactLayoutKey, autoLayout, resetLayout,
    relationshipEvidenceCount, graphOnlyFindings, graphRenderer, showViewportScope, showScopeEvidence,
    showContextControls, mobileListAvailable, mobileListActive, showChangesEntry, showLegend, graphPanelError,
    findingNodes, inspectRelationship, onNodeClick, onLargeGraphNodeSelect, onNodeMouseEnter, onNodeMouseLeave,
    selectFindingCard, runSearch, loadRootInvestigation, focusSearchResult, clearInvestigationMode, dismissRollup,
    returnToSummary, navigateRollupBreadcrumb, resetRollupToRoot, drillIntoRollup, investigateRollup, loadBlastRadius,
    retryGraph, graphTruncated,
  } = page;
  if (loadingSnapshots) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-ink-secondary">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading persisted graph snapshots...
      </div>
    );
  }

  if (error && snapshots.length === 0 && !selectedScanId) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-ink-secondary gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <button type="button" className="graph-chip-neutral" onClick={() => setSnapshotRetry((value) => value + 1)}>Retry loading snapshots</button>
        {rateLimited ? (
          <>
            <p className="text-sm">Graph temporarily rate-limited</p>
            <p className="text-xs text-ink-tertiary">
              The API is shedding load (HTTP 429). Wait a moment and retry — your
              snapshots are still there.
            </p>
          </>
        ) : (
          <>
            <p className="text-sm">Could not load the unified graph</p>
            <p className="text-xs text-ink-tertiary">
              Run a scan first so the API can persist graph snapshots.
            </p>
          </>
        )}
      </div>
    );
  }

  if (snapshots.length === 0 && !selectedScanId) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-ink-secondary gap-3">
        <ShieldAlert className="w-8 h-8 text-ink-tertiary" />
        <p className="text-sm">No graph snapshots found</p>
        <p className="text-xs text-ink-tertiary">
          Run a scan to persist the unified inventory and security graph.
        </p>
      </div>
    );
  }

  const scenarioComparisonPanel = (
    <GraphScenarioComparisonPanel
            scenario={selectedScenario}
            comparison={scenarioComparison}
            state={scenarioState}
            loading={loadingScenarioComparison}
            error={scenarioError}
            attackPathLens={attackPathLens}
            baseSnapshotAvailable={Boolean(
              selectedScenario &&
                snapshots.some(
                  (snapshot) => snapshot.scan_id === selectedScenario.base_scan_id,
                ),
            )}
            onStateChange={setScenarioState}
            onSwitchBase={() => {
              if (selectedScenario) {
                setSelectedScanId(selectedScenario.base_scan_id);
              }
            }}
            authoring={
              <GraphScenarioAuthoring
                scanId={selectedScanId}
                scenario={selectedScenario}
                session={session}
                canWrite={
                  roleCanConnect(
                    session?.role_summary?.role ?? session?.role,
                  ) &&
                  !session?.managed_trial_mode &&
                  session?.auth_method !== "managed_trial_oidc"
                }
                onSaved={(savedScenario) => {
                  setScenarios((current) => [
                    savedScenario,
                    ...current.filter(
                      (item) => item.scenario_id !== savedScenario.scenario_id,
                    ),
                  ]);
                  setSelectedScenarioId(savedScenario.scenario_id);
                  setScenarioState("proposed");
                  setScenarioRefreshKey((current) => current + 1);
                }}
              />
            }
          />
  );

  const selectedSnapshot = snapshots.find(item => item.scan_id === selectedScanId);
  const selectedSnapshotTitle = selectedSnapshot ? snapshotOptionLabel(selectedSnapshot)
    : selectedScanId && selectedScanId === currentEstateId ? "Current tenant estate" : selectedScanId || undefined;
  const snapshotViewControls = (
    <>
      {!investigationMode && !firstFramePending && flow.summary && (
        <div
          data-testid="graph-headline-metrics"
          className="rounded-xl border border-outline bg-surface/80 px-3 py-1.5 text-xs text-ink-secondary"
        >
          {formatGraphHeadline(flow.summary, snapshotAttackPathCount)}
          {flow.summary.costUsd30d > 0 && (
            <>
              {" · "}
              <span className="font-mono text-foreground">
                {flow.summary.costUsd30d.toLocaleString(undefined, {
                  style: "currency",
                  currency: "USD",
                  maximumFractionDigits:
                    flow.summary.costUsd30d < 100 ? 2 : 0,
                })}
              </span>{" "}
              spend 30d
            </>
          )}
          {flow.summary.expensiveExposed > 0 && (
            <>
              {" · "}
              <span className="font-mono text-red-700 dark:text-red-200">
                {flow.summary.expensiveExposed.toLocaleString()}
              </span>{" "}
              expensive & exposed
            </>
          )}
        </div>
      )}

      <select
        aria-label="Graph snapshot"
        value={selectedScanId}
        title={selectedSnapshotTitle}
        onChange={(event) => setSelectedScanId(event.target.value)}
        className="graph-page-select min-w-0 max-w-full truncate"
      >
        {selectedScanId && selectedScanId !== currentEstateId && !snapshots.some(item => item.scan_id === selectedScanId) && <option value={selectedScanId}>{selectedScanId}</option>}
        {currentEstateId && !snapshots.some(item => item.scan_id === currentEstateId) && <option value={currentEstateId}>Current tenant estate</option>}
        {snapshots.map((snapshot) => (
          <option key={snapshot.scan_id} value={snapshot.scan_id} title={snapshot.scan_id}>
            {snapshotOptionLabel(snapshot)}
          </option>
        ))}
      </select>

      {!rollupDecisionActive && <FullscreenButton />}
      {!rollupDecisionActive && presentation.enabled && !captureMode && displayNodes.length > 0 && graphRenderer.kind === "react-flow" && <details>
        <summary className="graph-page-action cursor-pointer">Layout</summary>
        <GraphInteractionToolbar
        editing={presentation.editing}
        hasSelection={Boolean(selectedNodeId)}
        onFitVisible={fitVisible}
        onFitSelection={fitSelection}
        onAutoLayout={autoLayout}
        onReset={resetLayout}
        onToggleEditing={presentation.toggleEditing}
      /></details>}
    </>
  );
  const scopeNavigation = scenarioState === "current" && !rollupUnavailable && (rollupView || investigationMode || selectedAttackPath) && <div className="shrink-0">
            {!rollupDecisionActive && rollupStack.length === 0 && <button type="button" onClick={returnToSummary} className="graph-page-action">All scopes</button>}
            {rollupStack.length > 0 && <nav aria-label="Investigation scope" className="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <button type="button" onClick={resetRollupToRoot} className="graph-page-action">All scopes</button>
              {rollupStack.map((crumb, index) => <ScopeBreadcrumbChip key={crumb.id} crumb={crumb} onClick={() => navigateRollupBreadcrumb(index)} />)}
            </nav>}
          </div>;
  const graphSearchForm = (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        void runSearch();
      }}
      className="flex min-w-[min(100%,16rem)] flex-1 items-center gap-2"
    >
      <input
        aria-label="Search nodes, tags, severities, or attributes"
        value={searchQuery}
        onChange={(event) => setSearchQuery(event.target.value)}
        placeholder="Search nodes, tags, severities, or attributes"
        className="graph-page-search"
      />
      <button
        type="submit"
        disabled={searching || !selectedScanId}
        className="graph-page-action"
      >
        {searching ? "Searching..." : "Search"}
      </button>
    </form>
  );


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
          <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
            <div className="shrink-0">
              <h1 className="text-lg font-semibold text-foreground sm:mt-1">
                Investigation
              </h1>

            </div>
            {narrowViewport && <details className="relative shrink-0" data-testid="mobile-graph-view">
              <summary className="graph-page-action cursor-pointer">Snapshot &amp; view</summary>
              <div className="absolute right-0 top-full z-30 mt-2 flex w-72 max-w-[calc(100vw-4rem)] flex-wrap gap-2 rounded-xl border border-outline bg-surface p-3 shadow-lg">
                {snapshotViewControls}
              </div>
            </details>}
          </div>

          <GraphLensSwitcher variant="compact" scanId={selectedScanId || undefined} />
          <div>
            {!investigationMode && <GraphAnalysisStatusBanner
              status={graphData?.stats.analysis_status?.attack_path_fusion}
              compact
            />}
          </div>
        </div>

        <div className="mt-1 sm:mt-3">
          {narrowViewport && scopeNavigation}

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

          <div className="relative mt-1">
          <GraphViewControls
            actions={!narrowViewport ? <div className="order-first flex min-w-0 flex-1 flex-wrap items-center gap-2">{scopeNavigation}{snapshotViewControls}{graphSearchForm}</div> : <details className="relative ml-auto" data-testid="mobile-graph-search">
              <summary className="graph-page-action cursor-pointer">Search graph</summary>
              <div className="absolute right-0 top-full z-30 mt-2 w-72 max-w-[calc(100vw-4rem)] rounded-xl border border-outline bg-surface p-3 shadow-lg">
                {graphSearchForm}
              </div>
            </details>}
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
            <div data-testid="graph-evidence-controls" className="space-y-3">
              {investigationMode && <label className="flex items-center gap-2 text-xs text-ink-secondary">Direction
                <select aria-label="Traversal direction" value={investigationDirection} onChange={event => void loadRootInvestigation({ rootId: investigationMode.rootId, rootLabel: investigationMode.rootLabel, direction: event.target.value as "forward" | "reverse" | "both" })} className="graph-page-action">
                  <option value="forward">Outgoing connections</option><option value="reverse">Incoming connections</option><option value="both">Both directions</option>
                </select>
              </label>}
                {!rollupCanvasOwnsPresentation && <p className="text-xs text-ink-secondary">
                  {graphScopeLabelForFilters(filters)} ·{" "}
                  {activeSnapshot
                    ? `${activeSnapshot.node_count.toLocaleString()} nodes · ${activeSnapshot.edge_count.toLocaleString()} edges`
                    : "Snapshot metadata unavailable"}
                  {graphTruncated ? " · bounded canvas" : " · complete current scope"}
                  {compressedGroupCount > 0
                    ? ` · ${compressedGroupCount.toLocaleString()} grouped scopes`
                    : ""}
                </p>}
              <div className="flex flex-wrap items-center gap-2">
                <GraphScenarioSelector
                  scenarios={scenarios}
                  selectedId={selectedScenarioId}
                  loading={loadingScenarios}
                  onSelect={(scenarioId) => {
                    setSelectedScenarioId(scenarioId);
                    setScenarioState("current");
                    if (!scenarioId) {
                      setScenarioComparison(null);
                      setScenarioError(null);
                    }
                  }}
                />
                <GraphEvidenceExportButton
                  scanId={selectedScanId || undefined}
                  filenamePrefix={
                    selectedScanId ? `scan-${selectedScanId}-graph` : undefined
                  }
                />
              </div>

          {!selectedScenario && scenarioComparisonPanel}

          {activeScopePreset === "assetDrift" && (
            <div className="mt-3 space-y-3">
              <div className="graph-callout-orange">
                <span>
                  Asset lifecycle drift lens — governance and{" "}
                  <span className="font-mono">exhibits_drift</span> edges with
                  drift incidents on estate containers.
                </span>
                <a
                  href="/drift"
                  className="graph-chip-orange"
                >
                  Open drift incidents
                </a>
              </div>
              <GraphDriftTimeline
                snapshots={historySnapshots}
                selected={diffPair}
                loading={loadingHistory}
                onSelect={(pair) => {
                  setDriftScrubberPair(pair);
                  setDriftLensActive(true);
                  setDriftFilter((current) =>
                    current === "all" ? "changed" : current,
                  );
                  if (pair.newScanId !== selectedScanId) {
                    setSelectedScanId(pair.newScanId);
                  }
                }}
              />
            </div>
          )}

          {(rollupEligible || loadingRollup || rollupError) &&
            !rollupDismissed && (
              <RollupNavigationPanel
                summary={rollupView}
                estateNodeCount={estateNodeCount}
                estateIssues={estateIssueLine(estateIssueSummary)}
                breadcrumbs={rollupStack}
                loading={loadingRollup}
                error={rollupError}
                unavailable={rollupUnavailable}
                active={rollupNavigationActive}
                decisionAvailable={rollupDecisionAvailable}
                decisionActive={rollupDecisionActive}
                onDismiss={dismissRollup}
                onRetry={retryGraph}
                onReset={resetRollupToRoot}
                onBreadcrumb={navigateRollupBreadcrumb}
                onDecisionMode={() => setRollupMapExpanded(false)}
              />
            )}

        </div>

        <div className="mt-2">
          {!rollupCanvasOwnsPresentation && <GraphSnapshotReceipt snapshot={activeSnapshot ?? null} scanId={selectedScanId} />}
          {!rollupCanvasOwnsPresentation && <GraphEvidenceSummary
            capturedAt={activeSnapshot?.created_at ?? null}
            returnedNodes={graphData?.completeness?.returned ?? graphData?.nodes.length ?? null}
            totalNodes={
              graphData?.completeness
                ? (graphData.completeness.total ?? null)
                : (graphData?.pagination.total ?? null)
            }
            snapshotTotalNodes={activeSnapshot?.node_count ?? null}
            evidencedEdges={relationshipEvidenceCount}
            totalEdges={graphData?.edges.length ?? null}
            completeness={
              graphData?.completeness?.status ??
              (graphData && graphData.nodes.length < graphData.pagination.total
                ? "truncated"
                : graphData
                  ? "complete"
                  : null)
            }
            completenessReason={graphData?.completeness?.reason ?? null}
            showCompleteness={!rollupCanvasOwnsPresentation}
            showRelationships={!rollupCanvasOwnsPresentation}
          />}
        </div>

        {/* One collapsed drawer keeps secondary controls off the default path.
            Its content uses flat sections rather than nested control drawers. */}
        <details className="mt-3 rounded-2xl border border-outline bg-background/70 group">
          <summary className="graph-drawer-summary">
            <div>
              <span className="text-[10px] uppercase tracking-[0.22em] text-ink-tertiary">
                Advanced controls
              </span>
              <p className="mt-1 text-xs text-ink-secondary">
                Scope, evidence overlays, drift lens, and the ranked path queue.
              </p>
            </div>
            <span className="text-[10px] uppercase tracking-[0.18em] text-ink-tertiary group-open:hidden">
              show
            </span>
            <span className="hidden text-[10px] uppercase tracking-[0.18em] text-ink-tertiary group-open:inline">
              hide
            </span>
          </summary>
          <div className="space-y-3 border-t border-outline/80 p-3">


        <GraphOperatorTools drift={lensDiff ? drift : null} driftActive={driftLensActive} driftFilter={driftFilter} comparedLabel={diffPair ? snapshotLabel(diffPair.oldScanId) : undefined}
          driftAttributeSummaries={driftAttributeSummaryList} showEdgeChanges={Boolean(driftLensActive && graphDiff)} edgeChanges={edgeChanges} edgeChangesLoading={loadingEdgeChanges} edgeChangesError={edgeChangesError}
          onDriftActive={next => { setDriftLensActive(next); if (!next) setDriftFilter("all"); }} onDriftFilter={setDriftFilter}
          evidenceActive={evidenceLensActive} evidenceFilter={evidenceFilter} evidenceCounts={evidenceCounts}
          onEvidenceActive={next => { setEvidenceLensActive(next); if (!next) setEvidenceFilter("all"); }} onEvidenceFilter={setEvidenceFilter} />

        <GraphAttackPathQueue paths={attackPaths} selected={selectedAttackPath} selectedKey={effectiveSelectedAttackPathKey} nodeById={graphNodeById}
          captureMode={captureMode} visibleHopCount={selectedVisibleHopCount} evidenceHopCount={selectedEvidenceHopCount}
          onSelect={key => { setReachabilitySummary(null); setReachabilityError(null); setSelectedAttackPathKey(key); }} />
          </div>
        </details>
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
          {/* One status bar: counts, evidence, context and legend, instead of four stacked bands. */}
          {!firstFramePending && (showViewportScope || showChangesEntry || showScopeEvidence || showContextControls || showLegend) && <div data-testid="graph-status-bar" className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1.5 border-b border-outline px-3 py-1.5">
          {showViewportScope && (
            <div className="flex min-w-0 max-w-full flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground" data-testid="graph-viewport-scope">
              <span>{scenarioContextIds ? "Changes and neighbors" : rollupNavigationActive ? (rollupView?.mode === "drilldown" ? `Within ${rollupView.node?.label ?? "selected scope"}` : "Scope overview") : "Graph"} · {displayNodes.length.toLocaleString()} {rollupNavigationActive ? "entities" : "nodes"} · {displayEdges.length.toLocaleString()} {rollupNavigationActive ? `aggregate link${displayEdges.length === 1 ? "" : "s"}` : `relationship${displayEdges.length === 1 ? "" : "s"}`}{scenarioElements.unconnected.length > 0 && ` · ${scenarioElements.unconnected.length} unconnected items`}</span>
              {selectedScenarioId && !attackPathLens && !selectedAttackPath && !investigationMode && <button type="button" onClick={() => setExpandedScenarioId(scenarioExpanded ? null : selectedScenarioId)} className="text-foreground underline underline-offset-4">{scenarioExpanded ? "Focus changes" : "Show full graph"}</button>}
              {showMiniMap && <button type="button" aria-pressed={minimapExpanded} onClick={() => setMinimapExpanded((value) => !value)} className="text-foreground underline underline-offset-4">{minimapExpanded ? "Hide minimap" : "Show minimap"}</button>}
              <button type="button" onClick={fitVisible} className="text-foreground underline underline-offset-4">Fit all</button>

          {investigationMode?.truncated && rootConnections && <span data-testid="graph-connection-progress">Showing {rootConnections.loaded} of {rootConnections.total} connections</span>}
          {investigationMode?.truncated && investigationMode.nodeCount < 24 && !loadingGraph && <button type="button" className="graph-page-action min-h-11 sm:min-h-7" onClick={() => void loadRootInvestigation({ rootId: investigationMode.rootId, rootLabel: investigationMode.rootLabel, direction: investigationDirection, nodeLimit: Math.min(24, Math.max(8, investigationMode.nodeCount * 2)) })}>Show more connections</button>}
            </div>
          )}
          {showChangesEntry && <GraphChangesEntry loading={graphChanges.loading || loadingDiff} error={graphChanges.error ?? diffError}
            headline={viewingCurrentEstate ? graphChanges.headline : snapshotChangesHeadline(graphDiff ? diffCounts : null, Boolean(previousSnapshot))}
            baseline={viewingCurrentEstate ? "previous scans" : "previous snapshot"} highlighting={driftLensEngaged}
            onOpen={() => { setChangesOpen(true); if (!viewingCurrentEstate) setComparisonRequested(true); }}
            onClearHighlight={() => { setDriftLensActive(false); setDriftFilter("all"); highlight.clear(); }} />}
          {showScopeEvidence && <GraphScopeEvidence edges={displayEdges} scope={graphRenderer.kind === "webgl" ? "loaded" : "visible"} inline />}
          {showContextControls && investigationContext && <GraphInvestigationContextControls inline
            groups={investigationContext.groups} selected={selectedContextGroup}
            visibleNodes={displayNodes.length} loadedNodes={scenarioElements.nodes.length}
            crossContextEdges={contextElements.crossContextEdges} onSelect={selectContextGroup} />}
          {showLegend && <div className="ml-auto text-right has-[details[open]]:ml-0 has-[details[open]]:basis-full"><GraphLegendDock items={legendItems} popover /></div>}
          </div>}
          <GraphChangesPanel open={changesOpen} changes={viewingCurrentEstate ? graphChanges.estateChanges : null}
            loading={graphChanges.loading} error={graphChanges.error}
            title={viewingCurrentEstate ? "Changed since previous scans" : "Changed since previous snapshot"}
            highlighting={driftLensEngaged} highlightLoading={highlight.loading} highlightError={highlight.error}
            highlightAvailable={!viewingCurrentEstate && Boolean(graphDiff) && driftIndex.hasChanges}
            selectedPair={viewingCurrentEstate ? driftScrubberPair : null}
            diffDetails={<GraphSnapshotDiff diff={graphDiff} counts={diffCounts} loading={loadingDiff} error={diffError} showCounts={!viewingCurrentEstate} pair={diffPair} />}
            onClose={() => setChangesOpen(false)} onHighlight={() => { setMobileGraphView("graph"); void highlight.highlight(); }}
            onOpenDiff={pair => { highlight.openPair(pair); setComparisonRequested(true); }}
            onInvestigateNode={(rootId, rootLabel) => { setChangesOpen(false); void loadRootInvestigation({ rootId, rootLabel }); }}
 />
          {mobileListAvailable && <div role="group" aria-label="Investigation view" className="flex gap-2">
            {(["list", "graph"] as const).map(view => <button key={view} type="button" aria-pressed={mobileGraphView === view} onClick={() => setMobileGraphView(view)}
              className="graph-page-action min-h-11 flex-1 aria-pressed:bg-surface-elevated">{view === "list" ? (investigationMode ? "List" : "Paths") : "Graph"}</button>)}
          </div>}
          {mobileListActive && (investigationMode
            ? <GraphConnectionsList rootId={investigationMode.rootId} nodes={displayNodes} edges={displayEdges} memberNodes={flowNodeById}
              onSelect={id => { const node = flowNodeById.get(id); if (node) onNodeClick({} as React.MouseEvent, node); }} />
            : <GraphPathList nodes={displayNodes} edges={displayEdges}
              onSelect={id => { const node = flowNodeById.get(id) ?? displayNodes.find(item => item.id === id); if (node) onNodeClick({} as React.MouseEvent, node); }} />)}
          <div ref={setGraphNavigationMount} className={mobileListActive ? "hidden" : undefined} />
          <div data-graph-adaptive-frame data-graph-annotations={graphLayoutKind === "asset-hierarchy" ? "on-demand" : undefined} className={`${mobileListActive ? "hidden " : ""}relative flex ${selectedAttackPath ? "h-[max(24rem,calc(100dvh-25rem))] sm:h-[clamp(24rem,50dvh,36rem)]" : selectedScenarioId ? "h-[max(24rem,calc(100dvh-25rem))] sm:h-[max(28rem,calc(100dvh-21rem))]" : "h-[var(--graph-adaptive-height,clamp(22rem,60dvh,48rem))]"} shrink-0 overflow-hidden rounded-lg border border-outline bg-surface`}>
          <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <GraphScenarioUnconnected
            nodes={scenarioElements.unconnected}
            notes={scenarioConnectionNotes}
            selectedId={selectedNodeId}
            onSelect={node => onNodeClick({} as React.MouseEvent, node)}
          />
          <div className="relative min-h-0 min-w-0 flex-1">
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
            <GraphRollupDecisionSurface
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
            <SigmaGraphOverview
              embedded
              nodes={displayNodes}
              edges={displayEdges}
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
          ) : (
            <ReactFlow
              style={readableGraphNodeStyle(graphViewport.zoom, Boolean(investigationContext), Boolean(investigationContext) && compactInvestigationTopology && !narrowViewport)}
              className={selectedScenarioId ? "scenario-context-canvas" : undefined}
              key={captureMode ? `lineage-capture:${scenarioExpanded ? "full" : "context"}` : `${presentation.storageKey}:${presentation.restoredSavedState ? "restored" : "initial"}:${scenarioExpanded ? "full" : "context"}`}
              nodes={presentation.nodes}
              edges={displayEdges}
              nodeTypes={lineageNodeTypesAdaptive}
              edgeTypes={relationshipEdgeTypes}
              // Ordinary views have one camera owner: GraphCanvasAutoFit.
              // A concurrent animated initial fit can resize LOD cards after
              // the measured fit has settled, leaving the root offscreen.
              fitView={Boolean(selectedScenarioId || selectedAttackPath) && !manualCamera && !presentation.hasSavedState && !presentation.restoredSavedState}
              fitViewOptions={manualCamera ? viewportOptions : initialViewportOptions}
              defaultViewport={presentation.restoredViewport ?? presentation.viewport}
              minZoom={0.05}
              maxZoom={2.5}
              zoomOnScroll={!captureMode}
              zoomOnPinch={!captureMode}
              panOnScroll={false}
              panOnDrag={!captureMode}
              preventScrolling={!captureMode}
              nodesDraggable={!captureMode && presentation.editing}
              nodesConnectable={false}
              nodesFocusable
              edgesFocusable
              elementsSelectable
              deleteKeyCode={null}
              onlyRenderVisibleElements={shouldVirtualizeReactFlowNodes({
                nodeCount: displayNodes.length,
                rollupActive: rollupNavigationActive,
                nodesInitialized,
              })}
              defaultEdgeOptions={{ type: "smoothstep" }}
              proOptions={{ hideAttribution: true }}
              onEdgeClick={(_event, edge) => inspectRelationship(edge)}
              onKeyDownCapture={event => {
                if (activateGraphNodeFromKeyboard(event)) return;
                if (event.key !== "Enter" && event.key !== " ") return;
                const id = event.target instanceof Element ? event.target.closest(".react-flow__edge")?.getAttribute("data-id") : null;
                const edge = id ? displayEdges.find(item => item.id === id) : undefined;
                if (edge) { event.preventDefault(); event.stopPropagation(); inspectRelationship(edge); }
              }}
              onNodeClick={onNodeClick}
              onNodeMouseEnter={onNodeMouseEnter}
              onNodeMouseLeave={onNodeMouseLeave}
              onNodesChange={presentation.onNodesChange}
              onNodeDragStop={presentation.onNodeDragStop}
              onMoveStart={(event) => { if (event) fitGeneration.current += 1; }}
              onMoveEnd={presentation.onMoveEnd}
              onPaneClick={() => {
                setSelectedRelationship(null);
                setSelectedNode(null);
                setSelectedNodeId(null);
                setHoveredNodeId(null);
                // #2257: empty-pane click clears the pinned focus too,
                // so the operator always has a single deterministic
                // gesture to "stop focusing".
                setPinnedFocusId(null);
                setReachabilitySummary(null);
                setReachabilityError(null);
                setBlastRadius(null);
                setBlastError(null);
              }}
            >
              <GraphCanvasAutoFit
                padding={investigationContext ? 0.25 : 0.08}
                navigationMount={graphNavigationMount}
                navigationIds={selectedAttackPath?.hops}
                enabled={!layoutPending && !selectedScenarioId && !selectedAttackPath}
                layoutKey={compactLayoutKey}
                anchorId={selectedNodeId ?? investigationMode?.rootId}
                inspector={Boolean(selectedNode || selectedRelationship) && !narrowViewport}
                preserveViewport={manualCamera || presentation.restoredSavedState}
                onLayoutAspect={setCanvasLayoutAspect}
              />
              <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
              <Controls {...(investigationContext ? { onFitView: fitVisible, fitViewOptions: { padding: 0.25, minZoom: 0.05, maxZoom: 1.25 } } : {})} orientation={selectedScenarioId ? "horizontal" : "vertical"} position="bottom-left" className={CONTROLS_CLASS} />
              {minimapExpanded && showMiniMap && (canvasLens !== "estate" || graphViewport.zoom >= 1) && (
                <MiniMap
                  position={narrowViewport ? "top-right" : "bottom-right"}
                  style={narrowViewport ? { width: 96, height: 64 } : undefined}
                  nodeColor={minimapNodeColor}
                  className={MINIMAP_CLASS}
                  bgColor={MINIMAP_BG}
                  maskColor={MINIMAP_MASK}
                />
              )}
            </ReactFlow>
          )}

          {(loadingGraph || loadingBlast) && graphData && <GraphRefreshOverlay label={loadingBlast ? "Computing blast radius · current view retained" : "Loading related assets · current view retained"} />}

          {layoutInput.omittedNodes > 0 && <div role="group" aria-label="Canvas context pages" className="mt-2 flex flex-wrap items-center gap-2 border-t border-outline pt-2 text-xs text-ink-secondary">
            <p role="status">{layoutInput.nodes.length} nodes on canvas · {layoutInput.omittedNodes} loaded nodes bundled off canvas.</p>
            <button type="button" disabled={layoutInput.page === 0} className="graph-page-action disabled:opacity-50" onClick={() => setCanvasPage(layoutInput.page - 1)}>Previous context</button>
            <button type="button" disabled={layoutInput.page + 1 >= layoutInput.pageCount} className="graph-page-action disabled:opacity-50" onClick={() => setCanvasPage(layoutInput.page + 1)}>Expand next context bundle</button>
          </div>}
          {graphTruncated && !rollupCanvasOwnsPresentation && (
            <details className="mt-2 border-t border-outline pt-2 text-xs text-ink-secondary" data-testid="graph-partial-view">
              <summary className="cursor-pointer">
                Partial view · {(graphData?.nodes.length ?? 0).toLocaleString()} nodes loaded
                {graphData?.completeness?.edges_truncated && " · relationships limited"}
                {activeSnapshot && activeSnapshot.node_count > (graphData?.nodes.length ?? 0)
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

          </div>
          </div>
          {!selectedNode && selectedRelationship?.scanId === selectedScanId && (() => {
            const aggregate = rollupNavigationActive ? rollupDisplayEdges.find(item => `rollup:${item.source}->${item.target}` === selectedRelationship.id) : undefined;
            if (aggregate && displayEdges.some(item => item.id === selectedRelationship.id)) return <GraphRollupRelationshipDetail
              edge={aggregate} scanId={selectedScanId}
              sourceLabel={rollupItems.find(item => item.id === aggregate.source)?.label || aggregate.source}
              targetLabel={rollupItems.find(item => item.id === aggregate.target)?.label || aggregate.target}
              onClose={() => setSelectedRelationship(null)} onInspectNode={rootId => void loadRootInvestigation({ rootId })} />;
            const edge = mergedGraphData?.edges.find(item => item.id === selectedRelationship.id);
            if (!edge || !displayEdges.some(item => item.id === edge.id)) return null;
            return <GraphRelationshipDetail edge={edge} scanId={selectedScanId} mobile={narrowViewport}
              sourceLabel={mergedGraphData?.nodes.find(item => item.id === edge.source)?.label || edge.source}
              targetLabel={mergedGraphData?.nodes.find(item => item.id === edge.target)?.label || edge.target}
              onClose={() => setSelectedRelationship(null)} />;
          })()}
          {selectedNode && (
            <GraphEntityDrawer
              variant={narrowViewport ? "overlay" : "docked"}
              data={selectedNode}
              suppliedDetail={selectedNodeDetail?.scanId === selectedScanId ? selectedNodeDetail.response : null}
              onInspectNode={(rootId) => void loadRootInvestigation({ rootId })}
              scanId={selectedScanId || undefined}
              enrich={Boolean(selectedScanId)}
              onOpenScope={rollupNavigationActive && selectedNodeId && selectedNode.attributes?.rollup_has_children === true ? () => {
                rollupAutoDescendRef.current = false;
                setRollupStack(current => current.at(-1)?.id === selectedNodeId ? current : [...current, { id: selectedNodeId, label: selectedNode.label }]);
                setSelectedNode(null);
                setSelectedNodeId(null);
                setPinnedFocusId(null);
                setHoveredNodeId(null);
              } : undefined}
              onExpandNeighbors={selectedNodeId ? () => void loadRootInvestigation({ rootId: selectedNodeId }) : undefined}
              onClose={() => {
                setSelectedNode(null);
                setSelectedNodeId(null);
                setPinnedFocusId(null);
                setHoveredNodeId(null);
              }}
              blastRadiusActive={blastRadius?.rootId === selectedNodeId}
              blastRadiusLoading={loadingBlast}
              onShowBlastRadius={
                selectedNodeId
                  ? () =>
                      void loadBlastRadius(
                        selectedNodeId,
                        selectedNode.label ?? selectedNodeId,
                      )
                  : undefined
              }
            />
          )}
          </div>
        </div>
        {selectedScenario && (
          <aside aria-label="Scenario decision" className="min-w-0 lg:min-h-0 lg:overflow-y-auto">
            {scenarioComparisonPanel}
          </aside>
        )}
      </div>
    </div>
  );
}
