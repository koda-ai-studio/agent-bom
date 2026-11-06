"use client";

import dynamic from "next/dynamic";
import { GraphIngressReceipt } from "@/components/graph-ingress-receipt";
import type { GraphPageModel } from "@/components/graph-page-view";
import type { useInvestigationFlowView } from "@/hooks/use-investigation-flow-view";

// Load evidence inspectors only when opened, keeping their code off the first-paint path.
const GraphEntityDrawer = dynamic(() => import("@/components/graph-entity-drawer").then(mod => mod.GraphEntityDrawer), { ssr: false });
const GraphRelationshipDetail = dynamic(() => import("@/components/graph-relationship-detail").then(mod => mod.GraphRelationshipDetail), { ssr: false });
const GraphRollupRelationshipDetail = dynamic(() => import("@/components/graph-relationship-detail").then(mod => mod.GraphRollupRelationshipDetail), { ssr: false });

/** Whichever inspector the current selection calls for. */
export function GraphSelectionPanels({ page, flowView }: { page: GraphPageModel; flowView: ReturnType<typeof useInvestigationFlowView> }) {
  const {
    selectedNode, selectedRelationship, narrowViewport, selectedScanId, rollupNavigationActive, rollupDisplayEdges, displayEdges, rollupItems, setSelectedRelationship, loadRootInvestigation,
    mergedGraphData, selectedNodeDetail, selectedNodeId, setRollupStack, rollupAutoDescendRef, setSelectedNode, setSelectedNodeId, setPinnedFocusId, setHoveredNodeId, blastRadius, loadingBlast, loadBlastRadius,
  } = page;
  const { disclosed } = flowView;
  return <>
          {flowView.receipt && !selectedNode && !selectedRelationship && <GraphIngressReceipt edge={flowView.receipt} mobile={narrowViewport} onClose={flowView.closeReceipt}
            targetLabel={disclosed.nodes.find(node => node.id === flowView.receipt?.target)?.data.label ?? String(flowView.receipt.target)} />}
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
              sourceType={mergedGraphData?.nodes.find(item => item.id === edge.source)?.entity_type}
              targetType={mergedGraphData?.nodes.find(item => item.id === edge.target)?.entity_type}
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
  </>;
}
