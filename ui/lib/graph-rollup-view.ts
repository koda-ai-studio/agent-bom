import { MarkerType, type Edge, type Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import type { GraphRollupContainer, GraphRollupEdge } from "@/lib/api-types";
import { assignCollisionScopes } from "@/lib/graph-occurrence-role";
import { severityRank } from "@/lib/severity";
import { FLOW_NODE_TYPES, lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";


const MIN_COLUMNS = 3;
// Scope cards keep summary facts visible. Reserve a separate lane for link labels.
const NODE_CARD_MAX_WIDTH = 280;
const NODE_COLUMN_GAP = 200;
const NODE_WIDTH = NODE_CARD_MAX_WIDTH + NODE_COLUMN_GAP;
const NODE_HEIGHT = 280;
// A graph canvas is landscape — roughly 2.2:1 at a laptop viewport. A grid
// whose own aspect ratio is far from that wastes the short axis and pays for it
// in zoom, because `fitView` scales to whichever axis runs out first.
const CANVAS_ASPECT = 2.2;

/** Columns that shape the grid like the canvas rather than like a column.
 *
 *  A fixed 3 columns turned the demo estate's 106 containers into a 996x4000
 *  tower, which `fitView` correctly resolved to scale 0.14 — labels at ~2.6px
 *  and half the nodes below the fold. Solving `(c*w)/((n/c)*h) = aspect` for
 *  `c` keeps the grid landscape at every estate size. */
function fittingColumns(count: number, width: number, height: number): number {
  if (count <= MIN_COLUMNS) return Math.max(1, count);
  const ideal = Math.sqrt((count * CANVAS_ASPECT * height) / width);
  return Math.min(count, Math.max(MIN_COLUMNS, Math.round(ideal)));
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
    severity: rollupDisplaySeverity(container) || undefined,
    description: rollupContainerSubtitle(container),
    attributes: {
      node_id: container.id,
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

export function buildRollupFlowGraph(
  containers: GraphRollupContainer[],
  options?: { columns?: number; edges?: GraphRollupEdge[] | undefined },
): { nodes: Node<LineageNodeData>[]; edges: Edge[] } {
  const compact = containers.length > 24;
  const width = compact ? 332 : NODE_WIDTH;
  const height = compact ? 112 : NODE_HEIGHT;
  const columns = Math.max(1, options?.columns ?? fittingColumns(containers.length, width, height));
  const nodes: Node<LineageNodeData>[] = containers.map((container, index) => {
    const nodeType = rollupEntityToNodeType(container.entity_type);
    const col = index % columns;
    const row = Math.floor(index / columns);
    return {
      id: container.id,
      type: FLOW_NODE_TYPES[nodeType],
      position: { x: col * width, y: row * height },
      data: { ...rollupContainerToNodeData(container), rollupCompact: compact },
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
      sourceHandle: `scope-source-${positions.get(edge.source)!.x === positions.get(edge.target)!.x ? (positions.get(edge.source)!.y < positions.get(edge.target)!.y ? "bottom" : "top") : positions.get(edge.source)!.x < positions.get(edge.target)!.x ? "right" : "left"}`,
      targetHandle: `scope-target-${positions.get(edge.source)!.x === positions.get(edge.target)!.x ? (positions.get(edge.source)!.y < positions.get(edge.target)!.y ? "top" : "bottom") : positions.get(edge.source)!.x < positions.get(edge.target)!.x ? "left" : "right"}`,
      // The aggregate count spans every listed kind; it is not a per-kind count.
      type: "smoothstep",
      label: `${edge.count.toLocaleString()} relationship${edge.count === 1 ? "" : "s"}`,
      data: { aggregate: edge, hoverDescription: `${edge.count} recorded relationship${edge.count === 1 ? "" : "s"} between entities · ${edge.directions?.join(", ") || "Direction not recorded"}. Select to inspect the aggregate.` },
      ariaLabel: `${edge.count} recorded relationship${edge.count === 1 ? "" : "s"} between entities; ${edge.directions?.length === 1 ? edge.directions[0] : edge.directions?.length ? "mixed directions" : "direction unavailable"}`,
      ...(edge.directions?.length === 1 && ["directed", "bidirectional"].includes(edge.directions[0]!)
        ? { markerEnd: { type: MarkerType.ArrowClosed, color: "var(--text-secondary)" } } : {}),
      ...(edge.directions?.length === 1 && edge.directions[0] === "bidirectional"
        ? { markerStart: { type: MarkerType.ArrowClosed, color: "var(--text-secondary)" } } : {}),
      animated: false,
      style: { strokeWidth: rollupEdgeWidth(edge.count) },
    }));
  return { nodes, edges };
}
