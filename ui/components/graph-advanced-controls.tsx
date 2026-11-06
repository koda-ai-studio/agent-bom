"use client";

import dynamic from "next/dynamic";
import { ASSET_BASE } from "@/lib/asset-base";
import { GraphEvidenceExportButton } from "@/components/graph-chrome";
import { GraphDriftTimeline } from "@/components/graph-drift-timeline";
import { GraphEvidenceSummary } from "@/components/graph-evidence-summary";
import { GraphScenarioPanel } from "@/components/graph-scenario-panel";
import { GraphSnapshotReceipt } from "@/components/graph-snapshot-receipt";
import { RollupNavigationPanel } from "@/components/graph-rollup-navigation-panel";
import { graphScopeLabelForFilters } from "@/components/lineage-filter";
import { estateIssueLine } from "@/lib/graph-issue-labels";
import { snapshotLabel } from "@/lib/snapshot-label";
import type { GraphPageModel } from "@/components/graph-page-view";

const GraphScenarioSelector = dynamic(() => import("@/components/graph-scenario-comparison").then(mod => mod.GraphScenarioSelector), { ssr: false });
const GraphOperatorTools = dynamic(() => import("@/components/graph-operator-tools").then(mod => mod.GraphOperatorTools), { ssr: false });
const GraphAttackPathQueue = dynamic(() => import("@/components/graph-attack-path-queue").then(mod => mod.GraphAttackPathQueue), { ssr: false });

/** Everything behind View & layers beyond the layer filters themselves. */
export function GraphAdvancedControls({ page }: { page: GraphPageModel }) {
  const {
    investigationMode, investigationDirection, loadRootInvestigation, rollupCanvasOwnsPresentation, filters, activeSnapshot, graphTruncated, compressedGroupCount,
    scenarios, selectedScenarioId, loadingScenarios, setSelectedScenarioId, setScenarioState, setScenarioComparison, setScenarioError, selectedScanId, selectedScenario,
    activeScopePreset, historySnapshots, diffPair, loadingHistory, setDriftScrubberPair, setDriftLensActive, setDriftFilter, setSelectedScanId,
    rollupEligible, loadingRollup, rollupError, rollupDismissed, rollupView, estateNodeCount, estateIssueSummary, rollupStack, rollupUnavailable, rollupNavigationActive,
    rollupDecisionAvailable, rollupDecisionActive, dismissRollup, retryGraph, resetRollupToRoot, navigateRollupBreadcrumb, setRollupMapExpanded,
    graphData, relationshipEvidenceCount, lensDiff, drift, driftLensActive, driftFilter, driftAttributeSummaryList, graphDiff, edgeChanges, loadingEdgeChanges, edgeChangesError,
    evidenceLensActive, setEvidenceLensActive, evidenceFilter, setEvidenceFilter, evidenceCounts, attackPaths, selectedAttackPath, effectiveSelectedAttackPathKey, graphNodeById,
    captureMode, selectedVisibleHopCount, selectedEvidenceHopCount, setReachabilitySummary, setReachabilityError, setSelectedAttackPathKey,
  } = page;
  return <>
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

          {!selectedScenario && <GraphScenarioPanel page={page} />}

          {activeScopePreset === "assetDrift" && (
            <div className="mt-3 space-y-3">
              <div className="graph-callout-orange">
                <span>
                  Asset lifecycle drift lens — governance and{" "}
                  <span className="font-mono">exhibits_drift</span> edges with
                  drift incidents on estate containers.
                </span>
                <a
                  href={`${ASSET_BASE}/drift`}
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
  </>;
}
