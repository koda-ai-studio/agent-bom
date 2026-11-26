import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { withoutFrames } from "@/lib/graph-exposure-spine";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";
import { semanticLayer } from "@/lib/graph-semantic-columns";

const ACCESS = new Set(["authenticates_as", "assumes", "has_permission", "can_access", "stores", "serves_model"]);
const FINDING = new Set(["vulnerable_to", "has_finding", "exhibits_drift"]);

/** A bounded, complete exposure witness leads the opening view. Supporting
 * context is reversible disclosure, never a new relationship or reach claim. */
export function storyContext(input: Node<LineageNodeData>[], inputEdges: Edge[], expanded: boolean) {
  const { nodes, edges } = withoutFrames(input, inputEdges);
  const visible = nodes.filter(node => !node.hidden);
  const path = visible.filter(node => node.data.semanticPathIndex !== undefined)
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex!).map(node => node.id);
  const unchanged = { nodes: input, edges: inputEdges, contextIds: new Set<string>() };
  if (visible.length > 24 || visible.some(node => node.data.rollup || node.data.attributes?.rollup_is_container === true)
    || path.length < 3 || path[0] !== INTERNET_ANCHOR_ID) return unchanged;
  if (path.slice(1).some((id, i) => !edges.some(edge => !edge.hidden && edge.source === path[i] && edge.target === id
    && (edge.data?.traversable === true || edge.source === INTERNET_ANCHOR_ID && edge.data?.displayOnly === true)))) return unchanged;
  const byId = new Map(visible.map(node => [node.id, node]));
  const kept = new Set(path);
  // Only follow recorded, outward access links. Blocked links remain visible as
  // context with their original traversability; they never extend the witness.
  for (let pass = 0; pass < visible.length; pass++) for (const edge of edges) {
    if (!edge.hidden && kept.has(edge.source) && byId.has(edge.target) && ACCESS.has(String(edge.data?.relationship))) kept.add(edge.target);
  }
  for (const edge of edges) {
    if (edge.hidden) continue;
    if (kept.has(edge.source) && byId.has(edge.target) && FINDING.has(String(edge.data?.relationship)) && semanticLayer(byId.get(edge.target)!) === "finding") kept.add(edge.target);
    if (kept.has(edge.target) && edge.data?.relationship === "affects" && byId.has(edge.source) && semanticLayer(byId.get(edge.source)!) === "finding") kept.add(edge.source);
  }
  // Scope remains visible context for the focused story. It does not pull its
  // unrelated children into the path or establish any access relationship.
  for (const node of visible) if (["account", "environment"].includes(String(node.data.nodeType)) && node.id !== INTERNET_ANCHOR_ID
    && edges.some(edge => !edge.hidden && edge.source === node.id && kept.has(edge.target) && ["contains", "hosts"].includes(String(edge.data?.relationship)))) kept.add(node.id);
  const contextIds = new Set(visible.filter(node => !kept.has(node.id) && !node.data.displayOnly).map(node => node.id));
  if (!contextIds.size) return unchanged;
  return {
    contextIds,
    nodes: nodes.map(node => ({ ...node, hidden: node.hidden || !expanded && contextIds.has(node.id),
      data: { ...node.data, connectedScope: true } })),
    edges: edges.map(edge => ({ ...edge, hidden: edge.hidden || !expanded && (contextIds.has(edge.source) || contextIds.has(edge.target)) })),
  };
}
