import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { MarkerType, type Edge, type Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import type { GraphRollupContainer, GraphRollupEdge } from "@/lib/api-types";
import { assignCollisionScopes } from "@/lib/graph-occurrence-role";
import { severityRank } from "@/lib/severity";
import { FLOW_NODE_TYPES, lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";


/** Retained for callers displaying a separate scope list; the graph stays left to right. */
export const PHONE_STACKED_SCOPE_LIMIT = 8;
export function phoneStacksScopes(narrow: boolean, scopes: number): boolean {
  return narrow && scopes > 0 && scopes <= PHONE_STACKED_SCOPE_LIMIT;
}

export function rollupEntityToNodeType(entityType: string): LineageNodeType {
  return lineageNodeTypeForEntity(entityType) ?? "cloudResource";
}

export function rollupContainerSubtitle(container: GraphRollupContainer): string {
  const parts: string[] = [];
  const aggregate = container.aggregate;
  const descendants = aggregate?.descendant_count ?? 0;
  if (descendants > 0) {
    parts.push(
      `${descendants} descendant${descendants === 1 ? "" : "s"}`,
    );
  } else if (container.direct_child_count > 0) {
    parts.push(
      `${container.direct_child_count} direct child${container.direct_child_count === 1 ? "" : "ren"}`,
    );
  }
  if (aggregate?.worst_severity && aggregate.worst_severity !== "none") {
    parts.push(`worst ${aggregate.worst_severity}`);
  }
  if (aggregate?.internet_exposed) {
    parts.push("internet exposed");
  }
  if (aggregate?.toxic_combo) {
    parts.push("toxic combo");
  }
  if (container.has_children) {
    parts.push("select to inspect scope");
  }
  return parts.join(" · ");
}

export function rollupDisplaySeverity(container: GraphRollupContainer): string {
  const own = container.severity?.toLowerCase() ?? "";
  const descendants = container.aggregate?.worst_severity?.toLowerCase() ?? "";
  return severityRank(own) >= severityRank(descendants) ? own : descendants;
}

function rollupContainerToNodeData(
  container: GraphRollupContainer,
): LineageNodeData {
  const nodeType = rollupEntityToNodeType(container.entity_type);
  const aggregate = container.aggregate;
  return {
    label: container.label,
    rollup: container,
    nodeType,
    entityType: container.entity_type,
    semanticLayer: container.semantic_layer,
    severity: rollupDisplaySeverity(container) || undefined,
    description: rollupContainerSubtitle(container),
    attributes: {
      node_id: container.id,
      cloud_provider: container.cloud_provider,
      rollup_has_children: container.has_children,
      rollup_is_container: container.is_container,
      rollup_descendant_count: aggregate?.descendant_count ?? 0,
    },
    highlighted: (aggregate?.worst_severity_rank ?? 0) >= 4,
    isCritical: aggregate?.worst_severity === "critical",
  };
}

/** Stroke width scaled to how many underlying edges collapsed into this one, so
 *  a 35-edge relationship reads as heavier than a 1-edge one at a glance. */
function rollupEdgeWidth(count: number): number {
  if (count >= 25) return 3;
  if (count >= 10) return 2.25;
  if (count >= 3) return 1.6;
  return 1;
}

/** A rolled-up link; `reverse` is the opposite direction drawn on the same line. */
export type DisplayRollupEdge = GraphRollupEdge & { reverse?: GraphRollupEdge };

/** Opposite links between two scopes share a line, so drawing both stacked their labels. */
export function mergeReciprocalRollupEdges(edges: readonly GraphRollupEdge[]): DisplayRollupEdge[] {
  const byPair = new Map(edges.map(edge => [`${edge.source}\u0000${edge.target}`, edge]));
  const merged: DisplayRollupEdge[] = [];
  const consumed = new Set<GraphRollupEdge>();
  for (const edge of edges) {
    if (consumed.has(edge)) continue;
    const reverse = edge.source === edge.target ? undefined : byPair.get(`${edge.target}\u0000${edge.source}`);
    if (!reverse) { merged.push(edge); continue; }
    consumed.add(reverse);
    const counts = edge.relationship_counts && reverse.relationship_counts
      ? Object.entries(reverse.relationship_counts).reduce<Record<string, number>>((total, [kind, count]) => ({ ...total, [kind]: (total[kind] ?? 0) + count }), { ...edge.relationship_counts })
      : null;
    merged.push({
      ...edge,
      count: edge.count + reverse.count,
      relationships: [...new Set([...edge.relationships, ...reverse.relationships])],
      relationship_counts: counts,
      reverse,
    });
  }
  return merged;
}

function oneWay(edge: GraphRollupEdge): boolean {
  return edge.directions?.length === 1 && ["directed", "bidirectional"].includes(edge.directions[0]!);
}

export function buildRollupFlowGraph(
  containers: GraphRollupContainer[],
  options?: { columns?: number; edges?: DisplayRollupEdge[] | undefined },
): { nodes: Node<LineageNodeData>[]; edges: Edge[] } {
  const nodes: Node<LineageNodeData>[] = containers.map(container => {
    const nodeType = rollupEntityToNodeType(container.entity_type);
    return {
      id: container.id,
      type: FLOW_NODE_TYPES[nodeType],
      position: { x: 0, y: 0 },
      data: rollupContainerToNodeData(container),
      ...(container.has_children ? { className: "cursor-pointer" } : {}),
    };
  });
  assignCollisionScopes(nodes);
  // The roll-up used to return no edges at all, so the canvas drew a grid of
  // disconnected cards and the view had to tell the reader that "aggregate
  // cards are not rendered relationship evidence" — a security graph admitting
  // it was not showing a graph. The API now aggregates the non-containment
  // edges between containers; drawing them is what makes this a topology.
  const positions = new Map(nodes.map(node => [node.id, node.position]));
  const present = new Set(positions.keys());
  const edges: Edge[] = (options?.edges ?? [])
    .filter((edge) => present.has(edge.source) && present.has(edge.target))
    .map((edge) => ({
      id: `rollup:${edge.source}->${edge.target}`,
      source: edge.source,
      target: edge.target,
      // The aggregate count spans every listed kind; it is not a per-kind count.
      type: "smoothstep",
      label: `${edge.count.toLocaleString()} relationship${edge.count === 1 ? "" : "s"}`,
      data: { aggregate: edge, hoverDescription: `${edge.count} recorded relationship${edge.count === 1 ? "" : "s"} between entities · ${edge.directions?.join(", ") || "Direction not recorded"}. Select to inspect the aggregate.` },
      ariaLabel: `${edge.count} recorded relationship${edge.count === 1 ? "" : "s"} between entities; ${edge.directions?.length === 1 ? edge.directions[0] : edge.directions?.length ? "mixed directions" : "direction unavailable"}`,
      ...(oneWay(edge) && (!edge.reverse || oneWay(edge.reverse))
        ? { markerEnd: { type: MarkerType.ArrowClosed, color: "var(--text-secondary)" } } : {}),
      ...((edge.reverse ? oneWay(edge) && oneWay(edge.reverse) : edge.directions?.length === 1 && edge.directions[0] === "bidirectional")
        ? { markerStart: { type: MarkerType.ArrowClosed, color: "var(--text-secondary)" } } : {}),
      animated: false,
      style: { strokeWidth: rollupEdgeWidth(edge.count) },
    }));
  return semanticGraphLayout(nodes, edges);
}
