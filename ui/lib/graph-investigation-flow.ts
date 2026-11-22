import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import type { Edge } from "@xyflow/react";
import { INVESTIGATION_NODE_LIMIT } from "@/lib/graph-neighbor-expansion";
import {
  ingressAssessment, isExposureEntry, isFinding, isPrincipal, isBlockedIdentityHop, isInternalService, ownership, relationshipOf,
  type FlowNode, type InvestigationFlow, type ReadingFlow, type SpecificFlow,
} from "@/lib/graph-flow-model";

export { withFindingOwners, type InvestigationFlow, type ReadingFlow, type SpecificFlow } from "@/lib/graph-flow-model";

/**
 * One canvas page. At this size the primary path still opens framed and legible with the rest
 * in rows beneath it; larger maps draw as an overview. Readability sets this, not cost:
 * computing a layout takes under 1ms at this size.
 */
export const FLOW_READABLE_NODE_LIMIT = INVESTIGATION_NODE_LIMIT;

export interface FlowResult {
  nodes: FlowNode[];
  edges: Edge[];
  scenario: ReadingFlow;
  applied: boolean;
  reason?: string | undefined;
  primaryPath: string[];
}

const NOTHING_TO_SHOW: Record<SpecificFlow, string> = {
  exposure: "No ingress, LoadBalancer or NodePort Service, or assessed internet ingress in this view.",
  identity: "No identities or roles in this view.",
  vulnerability: "No findings in this view.",
  inventory: "No recorded containment in this view.",
};

/** Whether each flow has its subject in the supplied nodes. */
export function flowAvailability(nodes: FlowNode[], edges: Edge[]): Record<SpecificFlow, { available: boolean; reason?: string }> {
  const visible = nodes.filter(node => !node.hidden);
  const ids = new Set(visible.map(node => node.id));
  const present: Record<SpecificFlow, boolean> = {
    exposure: visible.some(isExposureEntry),
    identity: visible.some(node => node.data.semanticLayer === "identity" || isPrincipal(node)),
    vulnerability: visible.some(isFinding),
    inventory: visible.some(node => node.data.nodeType === "account") || edges.some(edge => {
      const link = ownership(edge);
      return link && ids.has(link.parent) && ids.has(link.child);
    }),
  };
  const entry = (flow: SpecificFlow) => present[flow] ? { available: true } : { available: false, reason: NOTHING_TO_SHOW[flow] };
  return { exposure: entry("exposure"), identity: entry("identity"), vulnerability: entry("vulnerability"), inventory: entry("inventory") };
}

const isGroupedNode = (node: FlowNode) => Boolean(node.data.rollup) || node.type === "clusterPillNode";

/** Why no flow can arrange this view at all, whichever one is selected. */
export function flowUnavailableReason(nodes: FlowNode[]): string | undefined {
  if (nodes.some(isGroupedNode)) return "Flows need individual nodes. Expand the grouped items on this map to use one.";
  if (nodes.length > FLOW_READABLE_NODE_LIMIT) return `Flows read up to ${FLOW_READABLE_NODE_LIMIT} nodes so the path stays readable; this view has ${nodes.length}. Narrow it with filters or search.`;
  return undefined;
}

const SPECIFIC_FLOWS: readonly string[] = ["exposure", "identity", "vulnerability", "inventory"];
export function flowFromParam(value: string | null): InvestigationFlow {
  return value && SPECIFIC_FLOWS.includes(value) ? value as InvestigationFlow : "auto";
}

/** Preserve the server-ranked path when bounding a canvas page. */
export function flowPinnedIds(nodes: FlowNode[], _edges: Edge[], _requested: InvestigationFlow): string[] {
  void _edges; void _requested;
  return nodes.filter(node => !node.hidden && typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex!).map(node => node.id);
}

function inferredFlow(nodes: FlowNode[], edges: Edge[]): SpecificFlow {
  if (nodes.some(isExposureEntry) && edges.some(edge => relationshipOf(edge) === "exposed_to") || nodes.some(node => ingressAssessment(node))) return "exposure";
  if (edges.some(edge => ["has_permission", "can_access", "assumes"].includes(relationshipOf(edge)))) return "identity";
  return nodes.some(isFinding) ? "vulnerability" : "inventory";
}

/** Every view uses the same geometry. A view choice filters the subject; it
 * never derives an attack path or changes the server's evidence semantics. */
export function investigationFlow(input: FlowNode[], inputEdges: Edge[], requested: InvestigationFlow, _narrowViewport = false): FlowResult {
  void _narrowViewport;
  const scenario = requested === "auto" ? inferredFlow(input, inputEdges) : requested;
  const reason = flowUnavailableReason(input);
  if (reason) return { nodes: input, edges: inputEdges, scenario, applied: false, reason, primaryPath: [] };
  if (requested !== "auto") {
    const availability = flowAvailability(input, inputEdges)[requested];
    if (!availability.available) return { nodes: input, edges: inputEdges, scenario, applied: false, reason: availability.reason, primaryPath: [] };
  }
  const primary = flowPinnedIds(input, inputEdges, requested);
  const result = semanticGraphLayout(input, inputEdges, primary);
  const byId = new Map(input.map(node => [node.id, node]));
  const tokenless = new Set(inputEdges.filter(edge => isBlockedIdentityHop(edge) && byId.get(edge.source)?.data.attributes?.token_mounted === false).map(edge => edge.target));
  return { ...result,
    nodes: result.nodes.map(node => ({ ...node, data: { ...node.data, ...(input.length > 24 ? {} : { renderBand: "detail" as const }), ...(tokenless.has(node.id) ? { flowNote: "token not mounted" } : {}) } })),
    edges: result.edges.map(edge => {
      const source = byId.get(edge.source);
      const blocked = isBlockedIdentityHop(edge);
      const label = blocked ? source?.data.attributes?.token_mounted === false ? "Token not mounted" : "Not traversable"
        : relationshipOf(edge) === "exposed_to" && source && isInternalService(source) ? "Routes in cluster to" : edge.label;
      return { ...edge, label, data: { ...edge.data, flowStep: !blocked && edge.data?.pathEmphasis === true, ...(blocked ? { quietLabel: false } : {}) } };
    }), scenario, applied: true, primaryPath: primary };

}
