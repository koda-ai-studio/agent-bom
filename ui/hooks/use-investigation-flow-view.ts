"use client";

import { useCallback, useMemo, useState } from "react";
import type { Edge, Node, NodeChange } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { automaticFlowLabel } from "@/components/graph-flow-control";
import { useCloudFindingDisclosure } from "@/hooks/use-cloud-finding-disclosure";
import { useDisplayNodeMeasurements } from "@/hooks/use-display-node-measurements";
import { flowAvailability, flowFromParam, flowUnavailableReason, investigationFlow, type FlowResult, type InvestigationFlow, type SpecificFlow } from "@/lib/graph-investigation-flow";
import type { graphConnectionPreview } from "@/lib/graph-connection-preview";
import { GRAPH_CARD_ZOOM } from "@/lib/graph-adaptive-frame";
import { wrappedRankLayout } from "@/lib/graph-wrapped-ranks";
import { PREVIEW_LAYOUT } from "@/lib/graph-preview-layout";
import { separateCards } from "@/lib/graph-card-separation";
import { quietContextEdges, withHeldConnections } from "@/lib/graph-edge-quieting";

const WIDE_CARD = { "--graph-node-card-width": "300px" } as React.CSSProperties;

/** Finding nodes are hidden when their group collapses, so a selection on one must close first. */
export function selectionHiddenByCollapse(nodes: Node<LineageNodeData>[], selectedId: string | null) {
  return Boolean(selectedId && nodes.find(node => node.id === selectedId)?.data.readingOwner);
}

function writeFlowParam(flow: InvestigationFlow) {
  const url = new URL(window.location.href);
  if (flow === "auto") url.searchParams.delete("flow"); else url.searchParams.set("flow", flow);
  history.replaceState(null, "", url);
}

export interface FlowViewInput {
  presentation: {
    nodes: Node<LineageNodeData>[]; editing: boolean; hasPositionOverrides: boolean; hasSavedState: boolean; restoredSavedState: boolean; storageKey: string;
    onNodesChange: (changes: NodeChange<Node<LineageNodeData>>[]) => void;
  };
  edges: Edge[];
  /** Everything loaded, of which the canvas may draw only one page. */
  loaded: { nodes: Node<LineageNodeData>[]; edges: Edge[] };
  narrowViewport: boolean;
  requestedFlow: string | null;
  otherSurface: boolean;
  webglNodeCount: number | null;
  connectionPreview: ReturnType<typeof graphConnectionPreview<Node<LineageNodeData>, Edge>> | null | undefined;
  previewExpanded: boolean;
  setPreviewExpanded: (expanded: boolean) => void;
  selectedNodeId: string | null;
  /** Beyond the selection: nodes whose connections the operator is looking at right now. */
  focusNodeIds: (string | null)[];
  selectedRelationshipId: string | null;
  clearSelection: () => void;
  resetCamera: () => void;
}

/** Which flow is on screen, whether it could apply, and the disclosure layered over it. */
export function useInvestigationFlowView({ presentation, edges, loaded, narrowViewport, requestedFlow, otherSurface, webglNodeCount, connectionPreview, previewExpanded, setPreviewExpanded, selectedNodeId, focusNodeIds, selectedRelationshipId, clearSelection, resetCamera }: FlowViewInput) {
  const previewActive = Boolean(connectionPreview) && !previewExpanded;
  const kind = previewActive ? "auto" : flowFromParam(requestedFlow);
  const pausedReason = webglNodeCount !== null ? `Flows need a smaller view than this ${webglNodeCount.toLocaleString()}-node overview. Narrow it with filters or search.`
    : presentation.editing ? "Flows are paused while you edit the layout."
      : presentation.hasPositionOverrides ? "Your saved layout is showing. Reset it under Layout to use a flow." : undefined;
  const active = !otherSurface && !pausedReason;
  const [receiptId, setReceiptId] = useState<string | null>(null);

  const flow: FlowResult = useMemo(() => {
    if (!active) return { nodes: presentation.nodes, edges, scenario: "inventory", applied: false, primaryPath: [] };
    if (previewActive) return { nodes: wrappedRankLayout(presentation.nodes, PREVIEW_LAYOUT), edges, scenario: "inventory", applied: false, primaryPath: [] };
    return investigationFlow(presentation.nodes, edges, kind, narrowViewport);
  }, [active, previewActive, presentation.nodes, edges, kind, narrowViewport]);
  const disclosed = useCloudFindingDisclosure(flow.nodes, flow.edges, selectedNodeId, `${presentation.storageKey}:${kind}`,
    active || presentation.editing || presentation.hasSavedState || presentation.restoredSavedState);
  const [allEdgesShown, setAllEdgesShown] = useState(false);
  const annotated = useMemo(() => withHeldConnections(disclosed.nodes, disclosed.edges, allEdgesShown || presentation.editing), [disclosed.nodes, disclosed.edges, allEdgesShown, presentation.editing]);
  const measuredRaw = useDisplayNodeMeasurements(annotated, presentation.onNodesChange);
  // Saved and in-progress hand layouts are the operator's; only computed layouts are respaced.
  const respace = !presentation.editing && !presentation.hasPositionOverrides;
  const separated = useMemo(() => respace ? separateCards(measuredRaw.nodes) : measuredRaw.nodes, [respace, measuredRaw.nodes]);
  const measured = useMemo(() => ({ ...measuredRaw, nodes: separated }), [measuredRaw, separated]);
  const focusKey = JSON.stringify([selectedNodeId, ...focusNodeIds]);
  const quieted = useMemo(
    () => quietContextEdges(disclosed.edges, { showAll: allEdgesShown || presentation.editing, focusNodes: JSON.parse(focusKey) as (string | null)[], focusEdge: selectedRelationshipId }),
    [disclosed.edges, allEdgesShown, presentation.editing, focusKey, selectedRelationshipId],
  );

  // A preview or canvas page is a window, so what a flow could show is judged on the whole loaded map.
  const scope = previewActive && connectionPreview ? { nodes: connectionPreview.allNodes, edges: connectionPreview.allEdges } : loaded;
  const available = useMemo(() => {
    const result = flowAvailability(scope.nodes, scope.edges);
    return Object.fromEntries((Object.keys(result) as SpecificFlow[]).map(key => [key, result[key].available])) as Record<SpecificFlow, boolean>;
  }, [scope.nodes, scope.edges]);
  const unavailable = useMemo(() => flowUnavailableReason(presentation.nodes), [presentation.nodes]);

  const selectFlow = useCallback((next: InvestigationFlow) => {
    clearSelection();
    setReceiptId(null);
    resetCamera();
    if (next !== "auto" && previewActive) setPreviewExpanded(true);
    writeFlowParam(next);
  }, [clearSelection, previewActive, resetCamera, setPreviewExpanded]);

  const toggleFindingGroups = useCallback(() => {
    if (!disclosed.collapsed && selectionHiddenByCollapse(flow.nodes, selectedNodeId)) clearSelection();
    disclosed.toggleAll();
  }, [clearSelection, disclosed, flow.nodes, selectedNodeId]);

  const inspectDisplayEdge = useCallback((edge: Edge) => {
    if (edge.data?.relationship === "finding_group") {
      disclosed.nodes.find(node => node.id === edge.target)?.data.readingFindings?.toggle();
      return;
    }
    clearSelection();
    setReceiptId(edge.id);
  }, [clearSelection, disclosed.nodes]);
  const inspectDisplayNode = useCallback((node: Node<LineageNodeData>) => {
    if (node.data.readingFindings) { node.data.readingFindings.toggle(); return; }
    const link = disclosed.edges.find(edge => edge.data?.displayOnly && edge.source === node.id);
    if (link) inspectDisplayEdge(link);
  }, [disclosed.edges, inspectDisplayEdge]);

  const navigationIds = useMemo(() => {
    const positioned = [...disclosed.nodes.filter(node => !node.hidden)].sort((a, b) => a.position.x - b.position.x || a.position.y - b.position.y).map(node => node.id);
    if (flow.applied) return [...new Set([...flow.primaryPath, ...positioned])];
    return disclosed.available ? positioned : undefined;
  }, [disclosed.available, disclosed.nodes, flow.applied, flow.primaryPath]);

  return {
    kind, flow, disclosed, measured, active, previewActive, navigationIds, quieted, allEdgesShown, setAllEdgesShown, toggleFindingGroups, selectFlow, inspectDisplayEdge, inspectDisplayNode,
    cardStyle: flow.applied && !narrowViewport ? WIDE_CARD : undefined,
    primaryZoom: flow.scenario === "connections" && flow.applied ? GRAPH_CARD_ZOOM : undefined,
    anchorId: flow.primaryPath[0] ?? (active ? flow.nodes.find(node => !node.hidden && node.position.x === 0 && node.position.y === 0)?.id : undefined),
    receipt: receiptId ? disclosed.edges.find(edge => edge.id === receiptId) ?? null : null,
    closeReceipt: () => setReceiptId(null),
    control: otherSurface ? null : {
      value: kind, available, onChange: selectFlow,
      automaticLabel: automaticFlowLabel({ applied: flow.applied, scenario: flow.scenario, preview: previewActive }),
      disabledReason: pausedReason ?? unavailable,
      note: kind !== "auto" && !flow.applied ? flow.reason : undefined,
    },
    canonicalEdges: disclosed.edges.filter(edge => !edge.hidden && !edge.data?.displayOnly),
    canonicalVisibleNodes: disclosed.nodes.filter(node => !node.hidden && !node.data.displayOnly).length,
  };
}
