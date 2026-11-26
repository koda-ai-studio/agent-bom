import type { GraphRollupContainer, GraphRollupEdge } from "@/lib/api-types";
import type { Edge } from "@xyflow/react";
import { buildRollupFlowGraph, mergeReciprocalRollupEdges } from "@/lib/graph-rollup-view";
import { linkEndFans } from "@/lib/graph-compact-fan";
import { severityRank } from "@/lib/severity";
import { entitySource } from "@/lib/agent-source";

const FINDINGS = new Set(["misconfiguration", "vulnerability", "finding", "iac_finding"]);

/** Shared aggregate branches need a focused connection overview, even with few scopes.
 * This checks undirected layout topology, not directed reachability or attack paths. */
export function hasSharedScopeCycle(items: readonly GraphRollupContainer[], edges: readonly GraphRollupEdge[]): boolean {
  if (items.length < 4) return false;
  const parent = new Map(items.map(item => [item.id, item.id]));
  const pairs = new Set<string>();
  const root = (id: string): string => {
    while (parent.get(id) !== id) {
      parent.set(id, parent.get(parent.get(id)!)!);
      id = parent.get(id)!;
    }
    return id;
  };
  for (const { source, target } of edges) {
    if (source === target || !parent.has(source) || !parent.has(target)) continue;
    const pair = JSON.stringify([source, target].sort());
    if (pairs.has(pair)) continue;
    pairs.add(pair);
    const a = root(source), b = root(target);
    if (a === b) return true;
    parent.set(a, b);
  }
  return false;
}

/** Vertical distance between the scope's neighbour cards. */
export const SCOPE_PREVIEW_ROW = 150;
/** Neighbours drawn on each side of a scope: a laptop frame shows both sides at full size. */
const SCOPE_PREVIEW_PER_SIDE = 3;
/** How far a side of neighbours sits from the scope: wide enough that the drawn scope spans a laptop canvas,
 * narrower when both sides are drawn so its glyphs stay at full size. */
const SCOPE_PREVIEW_REACH = { one: 640, both: 500 } as const;

/** Which side of the scope a neighbour reads on: what points into the scope on the left, what it points to on the
 * right, the way the investigation canvas reads; a two-way or undirected link may take either side. */
function sideOf(root: string, neighbour: string, links: readonly GraphRollupEdge[]): "left" | "right" | "either" {
  const oneWay = (edge: GraphRollupEdge) => !(edge.directions ?? []).some(direction => direction !== "directed");
  const between = links.filter(edge => (edge.source === neighbour && edge.target === root) || (edge.source === root && edge.target === neighbour));
  if (between.length && between.every(edge => oneWay(edge) && edge.source === neighbour)) return "left";
  if (between.length && between.every(edge => oneWay(edge) && edge.source === root)) return "right";
  return "either";
}

/** A bounded selection of recorded links, never a synthesized attack path. */
export function buildScopePreview(items: GraphRollupContainer[], edges: GraphRollupEdge[], rootId?: string) {
  const byId = new Map(items.map(item => [item.id, item]));
  const incident = new Map<string, GraphRollupEdge[]>();
  for (const edge of edges) {
    if (!byId.has(edge.source) || !byId.has(edge.target) || edge.source === edge.target) continue;
    for (const id of [edge.source, edge.target]) incident.set(id, [...(incident.get(id) ?? []), edge]);
  }
  const roots = items.filter(item => !FINDINGS.has(item.entity_type) && incident.has(item.id))
    .sort((a, b) => (incident.get(b.id)?.length ?? 0) - (incident.get(a.id)?.length ?? 0) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  const root = rootId ? roots.find(item => item.id === rootId) : roots[0];
  if (!root) return null;
  const links = incident.get(root.id)!;
  const neighbors = [...new Set(links.map(edge => edge.source === root.id ? edge.target : edge.source))]
    .map(id => byId.get(id)!).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  const labels = new Set<string>();
  const diverse = neighbors.filter(item => {
    const family = FINDINGS.has(item.entity_type) ? item.label.match(/\b(?:CVE-\d{4}-\d{4,}|MCP-TOOL-\d+)\b/i)?.[0].toUpperCase() ?? item.label : item.id;
    const key = `${item.entity_type}:${family}`;
    if (labels.has(key)) return false;
    labels.add(key); return true;
  });
  const sides = { left: [] as GraphRollupContainer[], right: [] as GraphRollupContainer[] };
  for (const item of [...diverse, ...neighbors.filter(item => !diverse.includes(item))]) {
    const side = sideOf(root.id, item.id, links);
    const target = side === "either" ? (sides.right.length <= sides.left.length ? "right" : "left") : side;
    const fallback = target === "left" ? "right" : "left";
    if (sides[target].length < SCOPE_PREVIEW_PER_SIDE) sides[target].push(item);
    else if (side === "either" && sides[fallback].length < SCOPE_PREVIEW_PER_SIDE) sides[fallback].push(item);
  }
  const chosen = [...sides.left, ...sides.right];
  const ids = new Set(chosen.map(item => item.id));
  const selectedLinks = links.filter(edge => ids.has(edge.source === root.id ? edge.target : edge.source));
  const flow = buildRollupFlowGraph([root, ...chosen], { edges: mergeReciprocalRollupEdges(selectedLinks) });
  const providers = flow.nodes.map(node => entitySource(node.data));
  const sharedProvider = providers[0] && providers.every(provider => provider?.id === providers[0]!.id) ? providers[0] : null;
  const rows = Math.max(sides.left.length, sides.right.length);
  const reach = sides.left.length && sides.right.length ? SCOPE_PREVIEW_REACH.both : SCOPE_PREVIEW_REACH.one;
  const rootX = sides.left.length ? reach : 0;
  const left = new Set(sides.left.map(item => item.id));
  // Each side is centred on the scope's row.
  const place = (id: string) => {
    if (id === root.id) return { x: rootX, y: (rows - 1) * SCOPE_PREVIEW_ROW / 2 };
    const side = left.has(id) ? sides.left : sides.right;
    return { x: left.has(id) ? 0 : rootX + reach, y: (side.findIndex(item => item.id === id) + (rows - side.length) / 2) * SCOPE_PREVIEW_ROW };
  };
  const nodes = flow.nodes.map(node => ({ ...node,
    position: place(node.id),
    data: { ...node.data, findingAggregate: node.data.rollup?.aggregate, rollup: undefined, rollupCompact: false, highlighted: false,
      ...(sharedProvider ? { scopeContext: { provider: sharedProvider.id, environment: node.data.scopeContext?.environment ?? null } } : {}),
      attributes: { ...node.data.attributes, rollup_is_container: false },
    },
  }));
  // The preview has its own positions; routing from the full map is no longer valid.
  const fans = linkEndFans(flow.edges, new Map(nodes.map(node => [node.id, node.position])));
  return { root, roots, nodes, rows, sharedProvider,
    edges: flow.edges.map((edge): Edge => ({ ...edge,
      // Each link joins the facing sides of its two cards; context handles face the other way without reversing the
      // stored relationship direction.
      ...(left.has(edge.source) || left.has(edge.target)
        ? { sourceHandle: edge.source === root.id ? "context" : null, targetHandle: edge.target === root.id ? null : "context" }
        : { sourceHandle: edge.source === root.id ? null : "context", targetHandle: edge.target === root.id ? "context" : null }),
      data: { ...edge.data, arcDy: undefined, passesBehind: undefined, sourceFan: 0, targetFan: 0, ...fans.get(edge.id), labelVisibility: "auto", quietLabel: true, boundedOverview: true },
    })),
    availableRelationships: links.reduce((sum, edge) => sum + edge.count, 0),
    shownRelationships: selectedLinks.reduce((sum, edge) => sum + edge.count, 0),
  };
}
