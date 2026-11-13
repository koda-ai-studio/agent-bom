"use client";

import { Background, Controls, MiniMap, ReactFlow } from "@xyflow/react";
import { GraphCanvasAutoFit } from "@/components/graph-canvas-auto-fit";
import { useAnimatedLayout } from "@/hooks/use-animated-layout";
import { relationshipEdgeTypes } from "@/components/relationship-edge";
import { lineageNodeTypesAdaptive } from "@/components/lineage-nodes";
import { activateGraphNodeFromKeyboard } from "@/lib/graph-keyboard-selection";
import { disclosedGlyphSize, readableGraphNodeStyle } from "@/lib/graph-node-dimensions";
import { shouldVirtualizeReactFlowNodes } from "@/lib/graph-renderer-switch";
import { BACKGROUND_COLOR, BACKGROUND_GAP, CONTROLS_CLASS, MINIMAP_BG, MINIMAP_CLASS, MINIMAP_MASK, minimapNodeColor } from "@/lib/graph-utils";
import type { GraphPageModel } from "@/components/graph-page-view";
import type { useInvestigationFlowView } from "@/hooks/use-investigation-flow-view";

/** The readable node canvas; large maps use the WebGL overview instead. */
export function GraphFlowCanvas({ page, flowView }: { page: GraphPageModel; flowView: ReturnType<typeof useInvestigationFlowView> }) {
  const {
    graphViewport, investigationContext, narrowViewport, compactInvestigationTopology, selectedScenarioId, captureMode, presentation, scenarioExpanded,
    manualCamera, selectedAttackPath, viewportOptions, initialViewportOptions, displayNodes, displayEdges, rollupNavigationActive, nodesInitialized, inspectRelationship,
    onNodeClick, onNodeMouseEnter, onNodeMouseLeave, fitGeneration, setSelectedRelationship, setSelectedNode, setSelectedNodeId, setHoveredNodeId, setPinnedFocusId,
    setReachabilitySummary, setReachabilityError, setBlastRadius, setBlastError, connectionPreview, previewExpanded, graphNavigationMount, selectedNodeId, layoutPending,
    compactLayoutKey, investigationMode, selectedNode, selectedRelationship, setCanvasLayoutAspect, fitVisible, minimapExpanded, showMiniMap, canvasLens,
  } = page;
  const { disclosed, measured: measuredDisplay, quieted } = flowView;
  const roomyOverview = displayEdges.some(edge => edge.data?.roomyOverview === true);
  // Layout changes glide once (never while dragging or capturing); the camera frames the final positions.
  const motion = useAnimatedLayout(measuredDisplay.nodes, captureMode || presentation.editing, narrowViewport ? "narrow" : "wide", `${compactLayoutKey}:${flowView.kind}:${disclosed.key}`);
  return (
            <ReactFlow
              style={{ ...readableGraphNodeStyle(graphViewport.zoom, Boolean(investigationContext) || roomyOverview, (roomyOverview || Boolean(investigationContext) && compactInvestigationTopology) && !narrowViewport, displayNodes.length),
                ...flowView.cardStyle,
                ...(disclosed.available && !narrowViewport ? { "--graph-node-glyph-size": disclosedGlyphSize(graphViewport.zoom, displayNodes.length) } : {}) }}
              className={selectedScenarioId ? "scenario-context-canvas" : undefined}
              key={captureMode ? `lineage-capture:${scenarioExpanded ? "full" : "context"}` : `${presentation.storageKey}:${flowView.kind}:${presentation.restoredSavedState ? "restored" : "initial"}:${scenarioExpanded ? "full" : "context"}`}
              nodes={motion.nodes}
              edges={quieted.edges}
              nodeTypes={lineageNodeTypesAdaptive}
              edgeTypes={relationshipEdgeTypes}
              // Ordinary views have one camera owner: GraphCanvasAutoFit.
              // A concurrent animated initial fit can resize LOD cards after
              // the measured fit has settled, leaving the root offscreen.
              fitView={Boolean(selectedScenarioId) && !manualCamera && !presentation.hasSavedState && !presentation.restoredSavedState}
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
                boundedPreview={Boolean(connectionPreview) && !previewExpanded}
                padding={investigationContext ? 0.25 : 0.08}
                navigationMount={graphNavigationMount}
                navigationIds={selectedAttackPath?.hops ?? flowView.navigationIds}
                primaryIds={selectedAttackPath?.hops ?? (selectedNodeId ? undefined : flowView.flow.primaryPath)}
                primaryZoom={flowView.primaryZoom}
                enabled={!layoutPending && !motion.animating && !selectedScenarioId}
                layoutKey={`${compactLayoutKey}:${flowView.kind}:${disclosed.key}`}
                anchorId={selectedNodeId ?? investigationMode?.rootId ?? flowView.anchorId}
                inspector={Boolean(selectedNode || selectedRelationship) && !narrowViewport}
                preserveViewport={manualCamera || flowView.kind === "auto" && presentation.restoredSavedState}
                onLayoutAspect={setCanvasLayoutAspect}
              />
              <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
              <Controls {...(investigationContext || selectedScenarioId ? { onFitView: fitVisible, fitViewOptions: selectedScenarioId ? initialViewportOptions : { padding: 0.25, minZoom: 0.05, maxZoom: 1.25 } } : {})} orientation={selectedScenarioId ? "horizontal" : "vertical"} position="bottom-left" className={CONTROLS_CLASS} />
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
