"use client";

import { useCallback, useMemo } from "react";
import { graphPortraitLayout } from "@/lib/graph-portrait-layout";
import { withFindingDrilldowns } from "@/lib/graph-finding-disclosure";
import { Background, MiniMap, ReactFlow } from "@xyflow/react";
import { GraphCanvasAutoFit } from "@/components/graph-canvas-auto-fit";
import { LegibleFitControls } from "@/components/graph-legible-controls";
import { useAnimatedLayout } from "@/hooks/use-animated-layout";
import { relationshipEdgeTypes } from "@/components/relationship-edge";
import { lineageNodeTypesAdaptive } from "@/components/lineage-nodes";
import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";
import { disclosedGlyphSize, readableGraphNodeStyle } from "@/lib/graph-node-dimensions";
import { shouldVirtualizeReactFlowNodes } from "@/lib/graph-renderer-switch";
import { GRAPH_LEGIBLE_FIT_ZOOM, GRAPH_PHONE_LEGIBLE_FIT_ZOOM } from "@/lib/graph-adaptive-frame";
import { phoneStacksScopes } from "@/lib/graph-rollup-view";
import { BACKGROUND_COLOR, BACKGROUND_GAP, CONTROLS_CLASS, MINIMAP_BG, MINIMAP_CLASS, MINIMAP_MASK, minimapNodeColor } from "@/lib/graph-utils";
import type { GraphPageModel } from "@/components/graph-page-view";
import type { useInvestigationFlowView } from "@/hooks/use-investigation-flow-view";

/** The readable node canvas; large maps use the WebGL overview instead. */
export function GraphFlowCanvas({ page, flowView }: { page: GraphPageModel; flowView: ReturnType<typeof useInvestigationFlowView> }) {
  const {
    graphViewport, investigationContext, narrowViewport, compactInvestigationTopology, selectedScenarioId, captureMode, presentation, scenarioExpanded,
    manualCamera, selectedAttackPath, displayNodes, displayEdges, rollupNavigationActive, nodesInitialized, inspectRelationship,
    onNodeClick, onNodeMouseEnter, onNodeMouseLeave, fitGeneration, setSelectedRelationship, setSelectedNode, setSelectedNodeId, setHoveredNodeId, setPinnedFocusId,
    setReachabilitySummary, setReachabilityError, setBlastRadius, setBlastError, connectionPreview, previewExpanded, graphNavigationMount, selectedNodeId, layoutPending,
    compactLayoutKey, investigationMode, selectedNode, selectedRelationship, setCanvasLayoutAspect, fitVisible, minimapExpanded, showMiniMap, canvasLens,
    rollupMapExpanded, setRollupMapIllegible,
  } = page;
  // A scope map that cannot be read whole on this desktop canvas opens on the ranked overview; once the reader
  // chooses the map, it stays the map.
  const reportScopeMapFit = useCallback((fits: boolean) => { if (!fits) setRollupMapIllegible(true); }, [setRollupMapIllegible]);
  const { disclosed, measured: measuredDisplay, quieted } = flowView;
  const roomyOverview = displayEdges.some(edge => edge.data?.roomyOverview === true);
  // Layout changes glide once (never while dragging or capturing); the camera frames the final positions.
  const motion = useAnimatedLayout(measuredDisplay.nodes, captureMode || presentation.editing, narrowViewport ? "narrow" : "wide", `${compactLayoutKey}:${flowView.kind}:${disclosed.key}:${flowView.supporting.key}`);
  const nodes = useMemo(() => withFindingDrilldowns(motion.nodes, page.drillIntoRollup), [motion.nodes, page.drillIntoRollup]);
  const portrait = useMemo(() => narrowViewport ? graphPortraitLayout(nodes, quieted.edges) : { nodes, edges: quieted.edges }, [narrowViewport, nodes, quieted.edges]);
  return (
            <ReactFlow
              style={{ ...readableGraphNodeStyle(graphViewport.zoom, Boolean(investigationContext) || roomyOverview, (roomyOverview || Boolean(investigationContext) && compactInvestigationTopology) && !narrowViewport, portrait.nodes.filter(node => !node.hidden && node.type !== "boundaryFrame").length, flowView.supporting.available),
                ...flowView.cardStyle,
                ...(disclosed.available && !narrowViewport ? { "--graph-node-glyph-size": disclosedGlyphSize(graphViewport.zoom, portrait.nodes.filter(node => !node.hidden && node.type !== "boundaryFrame").length) } : {}) }}
              className={selectedScenarioId ? "scenario-context-canvas" : undefined}
              key={captureMode ? `lineage-capture:${scenarioExpanded ? "full" : "context"}` : `${presentation.storageKey}:${flowView.kind}:${presentation.restoredSavedState ? "restored" : "initial"}:${scenarioExpanded ? "full" : "context"}`}
              nodes={portrait.nodes}
              edges={portrait.edges}
              nodeTypes={lineageNodeTypesAdaptive}
              edgeTypes={relationshipEdgeTypes}
              // Ordinary views have one camera owner: GraphCanvasAutoFit.
              // A concurrent animated initial fit can resize LOD cards after
              // the measured fit has settled, leaving the root offscreen.
              fitView={false}
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
              defaultEdgeOptions={{ type: "relationship" }}
              proOptions={{ hideAttribution: true }}
              onEdgeClick={(_event, edge) => edge.data?.displayOnly ? flowView.inspectDisplayEdge(edge) : inspectRelationship(edge)}
              onKeyDownCapture={event => {
                if (activateGraphNodeFromKeyboard(event)) return;
                if (event.key !== "Enter" && event.key !== " ") return;
                const id = event.target instanceof Element ? event.target.closest(".react-flow__edge")?.getAttribute("data-id") : null;
                const edge = id ? disclosed.edges.find(item => item.id === id) : undefined;
                if (edge) { event.preventDefault(); event.stopPropagation(); if (edge.data?.displayOnly) flowView.inspectDisplayEdge(edge); else inspectRelationship(edge); }
              }}
              onNodeClick={(event, node) => {
                if (node.data.displayOnly) flowView.inspectDisplayNode(node);
                else { flowView.closeReceipt(); onNodeClick(event, node); }
              }}
              onNodeMouseEnter={(event, node) => { if (!node.data.readingGroup) onNodeMouseEnter(event, node); }}
              onNodeMouseLeave={onNodeMouseLeave}
              onNodesChange={measuredDisplay.onNodesChange}
              onNodeDragStop={presentation.onNodeDragStop}
              onMoveStart={(event) => { if (event) fitGeneration.current += 1; }}
              onMoveEnd={(event, viewport) => { if (flowView.kind === "auto") presentation.onMoveEnd(event, viewport); }}
              onPaneClick={() => {
                flowView.closeReceipt();
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
                boundedPreview={(Boolean(connectionPreview) && !previewExpanded) || (rollupNavigationActive && phoneStacksScopes(narrowViewport, displayNodes.length))}
                padding={investigationContext ? 0.25 : 0.08}
                navigationMount={graphNavigationMount}
                navigationIds={selectedAttackPath?.hops ?? flowView.navigationIds}
                primaryIds={selectedAttackPath?.hops ?? (selectedNodeId ? undefined : flowView.flow.primaryPath)}
                primaryZoom={flowView.primaryZoom}
                enabled={!layoutPending && !motion.animating}
                layoutKey={`${compactLayoutKey}:${flowView.kind}:${disclosed.key}:${flowView.supporting.key}:${selectedScenarioId ?? "estate"}`}
                anchorId={selectedNodeId ?? investigationMode?.rootId ?? (flowView.anchorId?.startsWith("display:") ? undefined : flowView.anchorId)}
                inspector={Boolean(selectedNode || selectedRelationship) && !narrowViewport}
                preserveViewport={manualCamera || flowView.kind === "auto" && presentation.restoredSavedState}
                onLayoutAspect={setCanvasLayoutAspect}
                onWholeFit={rollupNavigationActive && !narrowViewport && !rollupMapExpanded ? reportScopeMapFit : undefined}
              />
              <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
              <LegibleFitControls floor={narrowViewport ? GRAPH_PHONE_LEGIBLE_FIT_ZOOM : GRAPH_LEGIBLE_FIT_ZOOM} onFit={fitVisible} orientation={selectedScenarioId || narrowViewport ? "horizontal" : "vertical"} position={narrowViewport ? "top-right" : "bottom-left"} className={CONTROLS_CLASS} />
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
  );
}
