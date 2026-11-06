"use client";

import { FullscreenButton, GraphInteractionToolbar } from "@/components/graph-chrome";
import { ScopeBreadcrumbChip } from "@/components/graph-scope-breadcrumb";
import { snapshotOptionLabel } from "@/lib/snapshot-label";
import type { GraphPageModel } from "@/components/graph-page-view";

export function GraphSnapshotControls({ page }: { page: GraphPageModel }) {
  const { snapshots, selectedScanId, currentEstateId, setSelectedScanId, rollupDecisionActive, presentation, captureMode, displayNodes, graphRenderer, selectedNodeId, fitVisible, fitSelection, autoLayout, resetLayout } = page;
  const selectedSnapshot = snapshots.find(item => item.scan_id === selectedScanId);
  const selectedSnapshotTitle = selectedSnapshot ? snapshotOptionLabel(selectedSnapshot)
    : selectedScanId && selectedScanId === currentEstateId ? "Current tenant estate" : selectedScanId || undefined;
  return (
    <>


      <select
        aria-label="Graph snapshot"
        value={selectedScanId}
        title={selectedSnapshotTitle}
        onChange={(event) => setSelectedScanId(event.target.value)}
        className="graph-page-select w-64 min-w-0 max-w-full truncate sm:w-72"
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
}

export function GraphScopeNavigation({ page }: { page: GraphPageModel }) {
  const { scenarioState, rollupUnavailable, rollupView, investigationMode, selectedAttackPath, rollupDecisionActive, rollupStack, returnToSummary, resetRollupToRoot, navigateRollupBreadcrumb } = page;
  if (!(scenarioState === "current" && !rollupUnavailable && (rollupView || investigationMode || selectedAttackPath))) return null;
  return <div className="shrink-0">
            {!rollupDecisionActive && rollupStack.length === 0 && <button type="button" onClick={returnToSummary} className="graph-page-action">All scopes</button>}
            {rollupStack.length > 0 && <nav aria-label="Investigation scope" className="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <button type="button" onClick={resetRollupToRoot} className="graph-page-action">All scopes</button>
              {rollupStack.map((crumb, index) => <ScopeBreadcrumbChip key={crumb.id} crumb={crumb} onClick={() => navigateRollupBreadcrumb(index)} />)}
            </nav>}
  </div>;
}

export function GraphSearchForm({ page }: { page: GraphPageModel }) {
  const { runSearch, searchQuery, setSearchQuery, searching, selectedScanId } = page;
  return (
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
}
