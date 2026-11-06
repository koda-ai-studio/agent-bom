"use client";

import dynamic from "next/dynamic";
import { GraphChangesEntry } from "@/components/graph-changes-entry";
import { GraphLegendDock } from "@/components/graph-chrome";
import { GraphConnectionPreviewControls } from "@/components/graph-connection-preview-controls";
import { GraphFlowControl } from "@/components/graph-flow-control";
import { GraphHeadlineMetrics } from "@/components/graph-headline-metrics";
import { GraphInvestigationContextControls } from "@/components/graph-investigation-context-controls";
import { GraphScopeChangeStrip } from "@/components/graph-scope-change-strip";
import { GraphScopeEvidence } from "@/components/graph-scope-evidence";
import { GraphViewportScope } from "@/components/graph-viewport-scope";
import type { useRelationshipLabelControl } from "@/components/relationship-label-control";
import type { GraphPageModel } from "@/components/graph-page-view";
import type { useInvestigationFlowView } from "@/hooks/use-investigation-flow-view";
import { snapshotChangesHeadline } from "@/lib/graph-estate-changes";

const GraphChangesPanel = dynamic(() => import("@/components/graph-changes-panel").then(mod => mod.GraphChangesPanel), { ssr: false });
const GraphSnapshotDiff = dynamic(() => import("@/components/graph-snapshot-diff").then(mod => mod.GraphSnapshotDiff), { ssr: false });

type Props = { page: GraphPageModel; flowView: ReturnType<typeof useInvestigationFlowView>; relationshipLabels: ReturnType<typeof useRelationshipLabelControl> };

function GraphConnectionPreview({ page }: { page: GraphPageModel }) {
  const { connectionPreview, previewExpanded, setPreviewRoot, setPreviewExpanded, loadRootInvestigation } = page;
  if (!connectionPreview) return null;
  return <GraphConnectionPreviewControls preview={connectionPreview} expanded={previewExpanded}
    onRoot={setPreviewRoot} onExpanded={setPreviewExpanded}
    onExplore={() => void loadRootInvestigation({ rootId: connectionPreview.root.id, rootLabel: connectionPreview.root.data.label })} />;
}

/** A phone reads the graph first, so counts and preview actions sit under it rather than pushing it down. */
export function GraphPhoneFooter({ page, flowView }: Pick<Props, "page" | "flowView">) {
  if (!page.narrowViewport || page.firstFramePending) return null;
  return <div className="mt-2 space-y-2 px-1">
    <GraphViewportCounts page={page} flowView={flowView} />
    <GraphConnectionPreview page={page} />
  </div>;
}

function GraphChangesSummary({ page }: { page: GraphPageModel }) {
  const { showChangesEntry, viewingCurrentEstate, graphChanges, setChangesOpen, loadingDiff, diffError, graphDiff, diffCounts, previousSnapshot, driftLensEngaged, setComparisonRequested, setDriftLensActive, setDriftFilter, highlight } = page;
  return <>
          {showChangesEntry && viewingCurrentEstate && graphChanges.estateChanges && <GraphScopeChangeStrip changes={graphChanges.estateChanges} onOpen={() => setChangesOpen(true)} />}
          {showChangesEntry && <GraphChangesEntry loading={graphChanges.loading || loadingDiff} error={graphChanges.error ?? diffError}
            headline={viewingCurrentEstate ? graphChanges.headline : snapshotChangesHeadline(graphDiff ? diffCounts : null, Boolean(previousSnapshot))}
            baseline={viewingCurrentEstate ? "previous scans" : "previous snapshot"} highlighting={driftLensEngaged}
            onOpen={() => { setChangesOpen(true); if (!viewingCurrentEstate) setComparisonRequested(true); }}
            onClearHighlight={() => { setDriftLensActive(false); setDriftFilter("all"); highlight.clear(); }} />}
  </>;
}

function GraphViewSwitch({ page }: { page: GraphPageModel }) {
  const { mobileListAvailable, mobileGraphView, setMobileGraphView, investigationMode } = page;
  if (!mobileListAvailable) return null;
  return <div role="group" aria-label="Investigation view" className="flex shrink-0 gap-1">
    {(["list", "graph"] as const).map(view => <button key={view} type="button" aria-pressed={mobileGraphView === view} onClick={() => setMobileGraphView(view)}
      className="graph-page-action graph-action-compact min-h-11 aria-pressed:bg-surface-elevated aria-pressed:text-foreground">{view === "list" ? (investigationMode ? "List" : "Paths") : "Graph"}</button>)}
  </div>;
}

function GraphViewportCounts({ page, flowView }: Pick<Props, "page" | "flowView">) {
  const {
    showViewportScope, displayNodes, displayEdges, scenarioContextIds, rollupNavigationActive, rollupView, scenarioElements, selectedScenarioId, attackPathLens, selectedAttackPath, investigationMode, scenarioExpanded,
    setExpandedScenarioId, showMiniMap, minimapExpanded, setMinimapExpanded, fitVisible, rootConnections, loadingGraph, loadRootInvestigation, investigationDirection,
  } = page;
  const { disclosed } = flowView;
  // Asking for the whole map is asking for all of its connections too.
  const fitAll = () => { flowView.setAllEdgesShown(true); fitVisible(); };
  return showViewportScope ? <GraphViewportScope
    collapsedFindings={disclosed.collapsed} canonicalVisibleNodes={flowView.canonicalVisibleNodes} totalNodes={displayNodes.length} totalEdges={displayEdges.length}
    scopeLabel={scenarioContextIds ? "Changes and neighbors" : rollupNavigationActive ? (rollupView?.mode === "drilldown" ? `Within ${rollupView.node?.label ?? "selected scope"}` : "Scope overview") : "Graph"}
    aggregate={rollupNavigationActive} unconnected={scenarioElements.unconnected.length}
    scenarioToggle={selectedScenarioId && !attackPathLens && !selectedAttackPath && !investigationMode ? { expanded: scenarioExpanded, onToggle: () => setExpandedScenarioId(scenarioExpanded ? null : selectedScenarioId) } : undefined}
    minimap={showMiniMap ? { expanded: minimapExpanded, onToggle: () => setMinimapExpanded(value => !value) } : undefined}
    onFitAll={fitAll} findingsToggle={disclosed.available ? flowView.toggleFindingGroups : undefined}
    connections={investigationMode?.truncated && rootConnections ? rootConnections : undefined}
    onMoreConnections={investigationMode?.truncated && investigationMode.nodeCount < 24 && !loadingGraph ? () => void loadRootInvestigation({ rootId: investigationMode.rootId, rootLabel: investigationMode.rootLabel, direction: investigationDirection, nodeLimit: Math.min(24, Math.max(8, investigationMode.nodeCount * 2)) }) : undefined}
  /> : null;
}

/**
 * One status bar: counts, evidence, context and legend, instead of four stacked bands.
 * On a phone, and on the WebGL overview where flows are paused, the secondary pieces fold into Graph options.
 * Estate changes stay inline on the current estate: they are the answer to "what is different today".
 */
export function GraphStatusBar({ page, flowView, relationshipLabels }: Props) {
  const {
    firstFramePending, showViewportScope, showChangesEntry, showScopeEvidence, showContextControls, showLegend, mobileListAvailable, narrowViewport, viewingCurrentEstate, graphRenderer,
    displayNodes, scenarioElements, investigationContext, selectedContextGroup, contextElements, selectContextGroup, legendItems,
  } = page;
  const webgl = graphRenderer.kind === "webgl";
  const inlineChanges = (!narrowViewport && !webgl) || viewingCurrentEstate;
  const flowControl = flowView.control && <GraphFlowControl {...flowView.control} compact={narrowViewport} />;
  const scopeEvidence = (props: { compact?: boolean; label?: string }) => <GraphScopeEvidence edges={webgl ? relationshipLabels.edges : flowView.canonicalEdges} scope={webgl ? "loaded" : "visible"} inline {...props} />;
  if (firstFramePending) return null;
  if (!(showViewportScope || showChangesEntry || showScopeEvidence || showContextControls || showLegend || mobileListAvailable)) return null;
  return <div data-testid="graph-status-bar" className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1.5 border-b border-outline px-3 py-1.5 max-sm:gap-x-1 max-sm:px-0 max-sm:py-0.5">
    {!narrowViewport && <GraphHeadlineMetrics page={page} />}
    {narrowViewport && <GraphViewSwitch page={page} />}
    {!webgl && flowControl}
    {!narrowViewport && <GraphViewportCounts page={page} flowView={flowView} />}
    {!narrowViewport && <GraphConnectionPreview page={page} />}
    {inlineChanges && !narrowViewport && <GraphChangesSummary page={page} />}
    {!narrowViewport && showScopeEvidence && scopeEvidence({ compact: true })}
    {showContextControls && investigationContext && <GraphInvestigationContextControls inline
      groups={investigationContext.groups} selected={selectedContextGroup}
      visibleNodes={displayNodes.length} loadedNodes={scenarioElements.nodes.length}
      crossContextEdges={contextElements.crossContextEdges} onSelect={selectContextGroup} />}
    <details className="ml-auto text-xs open:w-full" data-testid="graph-options">
      <summary className="graph-page-action graph-action-compact ml-auto w-fit cursor-pointer max-sm:min-h-11">Graph options</summary>
      <div className="mt-2 flex w-full flex-wrap items-start gap-3 rounded-xl border border-outline bg-surface p-3">
        {narrowViewport && <GraphHeadlineMetrics page={page} />}
        {narrowViewport && flowView.control?.disabledReason && <p role="status" data-testid="graph-flow-status" className="text-ink-secondary">{flowView.control.disabledReason}</p>}
        {webgl && flowControl}
        {!inlineChanges && <GraphChangesSummary page={page} />}
        {!webgl && relationshipLabels.control}
        {showScopeEvidence && scopeEvidence({ label: "Relationship evidence breakdown" })}
        {showLegend && <GraphLegendDock items={legendItems} popover />}
      </div>
    </details>
    {narrowViewport && inlineChanges && <div className="w-full"><GraphChangesSummary page={page} /></div>}
  </div>;
}

export function GraphChangesDialog({ page }: { page: GraphPageModel }) {
  const { changesOpen, viewingCurrentEstate, graphChanges, driftLensEngaged, highlight, graphDiff, driftIndex, driftScrubberPair, diffCounts, loadingDiff, diffError, diffPair, setChangesOpen, setMobileGraphView, setComparisonRequested, loadRootInvestigation } = page;
  return <>
          {changesOpen && <GraphChangesPanel open={changesOpen} changes={viewingCurrentEstate ? graphChanges.estateChanges : null}
            loading={graphChanges.loading} error={graphChanges.error}
            title={viewingCurrentEstate ? "Changed since previous scans" : "Changed since previous snapshot"}
            highlighting={driftLensEngaged} highlightLoading={highlight.loading} highlightError={highlight.error}
            highlightAvailable={!viewingCurrentEstate && Boolean(graphDiff) && driftIndex.hasChanges}
            selectedPair={viewingCurrentEstate ? driftScrubberPair : null}
            diffDetails={<GraphSnapshotDiff diff={graphDiff} counts={diffCounts} loading={loadingDiff} error={diffError} showCounts={!viewingCurrentEstate} pair={diffPair} />}
            onClose={() => setChangesOpen(false)} onHighlight={() => { setMobileGraphView("graph"); void highlight.highlight(); }}
            onOpenDiff={pair => { highlight.openPair(pair); setComparisonRequested(true); }}
            onInvestigateNode={(rootId, rootLabel) => { setChangesOpen(false); void loadRootInvestigation({ rootId, rootLabel }); }}
 />}
  </>;
}
