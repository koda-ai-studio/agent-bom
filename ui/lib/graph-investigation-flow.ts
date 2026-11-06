import { MarkerType, type Edge } from "@xyflow/react";
import { INVESTIGATION_NODE_LIMIT } from "@/lib/graph-neighbor-expansion";
import { bestStart, collectSteps, flowRowGap, FLOW_COLUMN_GAP, longestRanks, nearestRanks, placeFlow, primaryPath } from "@/lib/graph-flow-layout";
import {
  flowRoots, ingressAssessment, isBlockedIdentityHop, isExposureEntry, isFinding, isInternalService, isPrincipal, ownership, relationshipOf, withFindingOwners,
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

const CONTEXT_EDGE_OPACITY = 0.3;
const DENSE_MAP_NODES = 24;
/** A map this small has no tangle to quiet: every connection it draws stays legible. */
const QUIET_MIN_NODES = 16;

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
    identity: visible.some(isPrincipal),
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

/** Everything the flow would read in order, so a bounded canvas page cannot leave out its entry. */
export function flowPinnedIds(nodes: FlowNode[], edges: Edge[], requested: InvestigationFlow): string[] {
  const flow = requested === "auto" ? inferredFlow(nodes, edges) : requested;
  // A view Automatic will not rearrange keeps its existing page contents.
  if (requested === "auto" && !automaticApplies(nodes, flow)) return [];
  const visible = nodes.filter(node => !node.hidden), byId = new Map(visible.map(node => [node.id, node]));
  const roots = flowRoots(flow, visible, edges).map(node => node.id);
  return [...longestRanks(roots, collectSteps(flow, byId, edges).next).keys()];
}

/** Above this, Automatic keeps a dense map's existing layout; choosing a flow still applies it up to the limit. */
const AUTOMATIC_NODE_LIMIT = 80;

function automaticApplies(nodes: FlowNode[], flow: SpecificFlow) {
  return flow !== "inventory" && nodes.length <= AUTOMATIC_NODE_LIMIT && nodes.some(node => isExposureEntry(node) || ["account", "cluster"].includes(node.data.nodeType));
}

function inferredFlow(nodes: FlowNode[], edges: Edge[]): SpecificFlow {
  if (nodes.some(isExposureEntry) && edges.some(edge => relationshipOf(edge) === "exposed_to") || nodes.some(node => ingressAssessment(node))) return "exposure";
  if (edges.some(edge => ["has_permission", "can_access", "assumes"].includes(relationshipOf(edge)))) return "identity";
  return nodes.some(isFinding) ? "vulnerability" : "inventory";
}

/** Display context from a target-bound assessment, never from names, IPs or a public flag.
 * This neither adds a persisted asset nor upgrades an attack-path receipt. */
function withInternetContext(nodes: FlowNode[], edges: Edge[]) {
  const extra: FlowNode[] = [], links: Edge[] = [];
  for (const node of nodes) {
    const assessment = ingressAssessment(node);
    if (!assessment) continue;
    // One boundary per target: never merge unrelated accounts or snapshots through a global Internet node.
    const id = `display:internet:${node.id}`;
    if (nodes.some(item => item.id === id)) continue;
    extra.push({
      id, initialWidth: 240, initialHeight: 300, draggable: false, type: "cloudResourceNode", position: { x: 0, y: 0 }, ariaLabel: `Internet, assessed ingress to ${node.data.label}`,
      data: { label: "Internet", nodeType: "cloudResource", displayOnly: true, displayTargetId: node.id, readingLabel: "Assessed ingress · snapshot", attributes: { resource_type: "internet_boundary" } },
    });
    // A recorded assessment, not a tested route, so it must not outweigh a recorded edge.
    links.push({
      id: `${id}:ingress`, source: id, target: node.id, type: "smoothstep", markerEnd: { type: MarkerType.ArrowClosed }, ariaLabel: `Assessed ingress from Internet to ${node.data.label}`,
      style: { stroke: "var(--text-secondary)", strokeWidth: 1, strokeDasharray: "6 3" }, label: "Assessed ingress",
      data: { relationship: "exposed_to", displayOnly: true, traversable: false, evidence: assessment, evidenceMode: "inferred", individualLabel: true, quietLabel: true, directionEmphasis: true },
    });
  }
  return { nodes: [...nodes, ...extra], edges: [...edges, ...links] };
}

function edgeHandles(edge: Edge, positions: Map<string, { x: number; y: number }>) {
  const source = positions.get(edge.source), target = positions.get(edge.target);
  if (!source || !target) return {};
  if (source.x > target.x) return { sourceHandle: "context", targetHandle: "context" };
  if (!ownership(edge) || target.y >= source.y) return {};
  // The provider mark sits on the top-right of the glyph, so an upward edge leaves from top centre,
  // unless another card sits directly above it; the side handles then route around that card.
  const blocked = [...positions.values()].some(at => at.x === source.x && at.y < source.y && at.y >= target.y && at !== target);
  return blocked ? {} : { sourceHandle: "context-up" };
}

function readingCaption(edge: Edge, byId: Map<string, FlowNode>) {
  if (isBlockedIdentityHop(edge)) {
    const source = byId.get(edge.source);
    return { label: source?.data.attributes?.token_mounted === false ? "Token not mounted" : "Not traversable", quietLabel: false };
  }
  const source = byId.get(edge.source);
  return relationshipOf(edge) === "exposed_to" && source && isInternalService(source) ? { label: "Routes in cluster to" } : {};
}

/** Layout changes reading order, never relationship direction, reachability or finding identity. */
export function investigationFlow(input: FlowNode[], inputEdges: Edge[], requested: InvestigationFlow, narrowViewport = false): FlowResult {
  const inferred = requested === "auto" ? inferredFlow(input, inputEdges) : requested;
  const untouched = (reason?: string): FlowResult => ({ nodes: input, edges: inputEdges, scenario: inferred, applied: false, reason, primaryPath: [] });
  // A map too large to fit on one screen still needs a start and a reading order. Unlike a flow,
  // this makes no claim about what a group hides, so a grouped map can be read this way too.
  const grouped = input.some(isGroupedNode);
  const readAsConnections = requested === "auto" && input.length > DENSE_MAP_NODES && input.length <= FLOW_READABLE_NODE_LIMIT && (grouped || !automaticApplies(input, inferred));
  const declined = readAsConnections ? undefined : flowUnavailableReason(input);
  if (declined) return untouched(declined);
  if (requested === "auto" && !readAsConnections && !automaticApplies(input, inferred)) return untouched();
  const scenario: ReadingFlow = readAsConnections ? "connections" : inferred;
  if (scenario !== "connections") {
    const availability = flowAvailability(input, inputEdges)[scenario];
    if (!availability.available) return untouched(availability.reason);
  }

  // Connections shows every loaded record; only a chosen flow groups findings under their owner.
  const owned = scenario === "connections" ? input : withFindingOwners(input, inputEdges);
  const { nodes, edges } = scenario === "exposure" ? withInternetContext(owned, inputEdges) : { nodes: owned, edges: inputEdges };
  const visible = nodes.filter(node => !node.hidden), byId = new Map(visible.map(node => [node.id, node]));
  const displayFirst = (id: string) => Number(!byId.get(id)!.data.displayOnly);
  const roots = flowRoots(scenario, visible, edges).map(node => node.id).sort((a, b) => displayFirst(a) - displayFirst(b) || a.localeCompare(b));
  const steps = collectSteps(scenario, byId, edges);
  const connections = scenario === "connections";
  // Start from the root that owns the most, so its chain is what opens on the top row.
  const start = connections ? bestStart(roots, steps, byId) : undefined;
  const ranks = connections ? nearestRanks(roots.slice().sort((a, b) => Number(start?.has(b)) - Number(start?.has(a))), steps.next) : longestRanks(roots, steps.next);
  const primary = primaryPath(scenario, ranks, steps, byId, start);
  const positions = placeFlow({ visible, ranks, primary, steps, edges, narrow: narrowViewport, strictColumns: !connections });
  const stepped = new Set([...steps.next].flatMap(([from, list]) => list.map(to => `${from}|${to}`)));
  // Also on the card: an edge caption can be hidden when it would collide with another card.
  const tokenless = new Set(edges.filter(edge => isBlockedIdentityHop(edge) && byId.get(edge.source)?.data.attributes?.token_mounted === false).map(edge => edge.target));
  const pathLinks = new Set(primary.slice(1).flatMap((id, index) => [`${primary[index]}|${id}`, `${id}|${primary[index]}`]));
  const rowGap = flowRowGap(narrowViewport);
  /** More than one grid cell away or running against the reading order, so the line has to go around other cards. */
  const roundabout = (edge: Edge) => {
    const from = positions.get(edge.source), to = positions.get(edge.target);
    return Boolean(from && to) && (from!.x > to!.x || Math.abs(from!.x - to!.x) > FLOW_COLUMN_GAP || Math.abs(from!.y - to!.y) > rowGap);
  };
  return {
    scenario, applied: true, primaryPath: primary,
    // Connections keeps the zoom band, so an operator zooming out still gets the summary renderer.
    nodes: nodes.map(node => ({ ...node, position: positions.get(node.id) ?? node.position, ...(scenario === "connections" ? {} : { style: { ...node.style, minHeight: 320 } }),
      data: { ...node.data, evidenceFlow: true, ...(scenario === "connections" ? {} : { renderBand: "detail" as const }), ...(tokenless.has(node.id) ? { flowNote: "token not mounted" } : {}) } })),
    edges: edges.map(edge => {
      const { label, ...caption } = readingCaption(edge, byId);
      const key = `${edge.source}|${edge.target}`, reverse = `${edge.target}|${edge.source}`;
      const flowStep = ranks.has(edge.source) && ranks.has(edge.target) && (stepped.has(key) || stepped.has(reverse));
      return { ...edge, ...edgeHandles(edge, positions), ...(label ? { label } : {}),
        // The eye should follow the path first; everything recorded stays drawn and inspectable.
        style: { ...edge.style, opacity: pathLinks.has(key) ? 1 : flowStep ? 0.55 : CONTEXT_EDGE_OPACITY },
        data: { ...edge.data, quietLabel: true, individualLabel: true, directionEmphasis: true, flowStep, ...caption,
          // A chosen flow's steps are its subject, and what surrounds them waits; on a plain map only the roundabout lines do.
          quietUntilFocus: visible.length >= QUIET_MIN_NODES && !pathLinks.has(key) && (connections ? roundabout(edge) : !flowStep) } };
    }),
  };
}
