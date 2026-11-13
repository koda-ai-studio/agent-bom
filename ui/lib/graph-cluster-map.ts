/**
 * The grouped full map: request state, bundled-edge labels and a tier-column layout.
 *
 * The server groups the snapshot and counts every bundled edge exactly; this
 * module only decides where each group, member and "+K more" card sits.
 * Groups read left to right in the order an exposure travels (scope, AI layer,
 * MCP servers, packages, findings, identities, cloud and data); within a
 * column risky groups lead and the rest are ordered to cross as few bundles
 * as possible. On a phone the tiers stack top to bottom instead.
 */
import type { components } from "@/lib/api-schema.generated";
import { GRAPH_EDGE_KIND_META, isGraphEdgeKind } from "@/lib/graph-schema.generated";

export type ClusterMapResponse = components["schemas"]["GraphClusterMapResponse"];
export type ClusterMapNode = components["schemas"]["GraphClusterMapNode"];
export type ClusterMapEdge = components["schemas"]["GraphClusterMapEdge"];

/** Mirrors the server's FIRST_FRAME_ELEMENT_BUDGET: what a first frame may draw. */
export const CLUSTER_MAP_ELEMENT_BUDGET = 60;
export const CLUSTER_MAP_MEMBER_LIMIT = 8;

export interface ClusterMapState {
  expanded: string[];
  pages: Record<string, number>;
  riskyOnly: boolean;
  focus: string | null;
}

export const INITIAL_CLUSTER_MAP_STATE: ClusterMapState = { expanded: [], pages: {}, riskyOnly: false, focus: null };

export function clusterMapParams(scanId: string | undefined, state: ClusterMapState, memberLimit = CLUSTER_MAP_MEMBER_LIMIT): URLSearchParams {
  const params = new URLSearchParams();
  if (scanId) params.set("scan_id", scanId);
  for (const id of state.expanded) params.append("expand", id);
  for (const [id, offset] of Object.entries(state.pages)) if (offset > 0 && state.expanded.includes(id)) params.append("page", `${offset}:${id}`);
  if (state.riskyOnly) params.set("risky_only", "true");
  if (state.focus) params.set("focus", state.focus);
  params.set("member_limit", String(memberLimit));
  return params;
}

/** Expanding opens a group in place; collapsing it forgets its page and any focus inside it. */
export function toggleClusterExpanded(state: ClusterMapState, id: string, focusClusterId?: string | null): ClusterMapState {
  if (state.expanded.includes(id) || focusClusterId === id) {
    const pages = { ...state.pages };
    delete pages[id];
    return { ...state, expanded: state.expanded.filter(item => item !== id), pages, focus: focusClusterId === id ? null : state.focus };
  }
  return { ...state, expanded: [...state.expanded, id] };
}

export function pageCluster(state: ClusterMapState, id: string, offset: number): ClusterMapState {
  return { ...state, expanded: state.expanded.includes(id) ? state.expanded : [...state.expanded, id], pages: { ...state.pages, [id]: Math.max(0, offset) } };
}

export function relationshipLabel(relationship: string): string {
  return isGraphEdgeKind(relationship) ? GRAPH_EDGE_KIND_META[relationship].label : relationship.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

/** "Depends On ×38"; a bundle of several kinds names the largest and how many others it carries. */
export function bundleLabel(edge: Pick<ClusterMapEdge, "count" | "relationships">): string {
  const [top, ...rest] = edge.relationships;
  if (!top) return `×${edge.count.toLocaleString()}`;
  const head = `${relationshipLabel(top.relationship)} ×${top.count.toLocaleString()}`;
  return rest.length ? `${head} +${rest.length} more` : head;
}

export function bundleTitle(edge: Pick<ClusterMapEdge, "count" | "relationships">): string {
  return `${edge.count.toLocaleString()} relationships: ${edge.relationships.map(item => `${relationshipLabel(item.relationship)} ×${item.count.toLocaleString()}`).join(", ")}`;
}

export interface PlacedClusterNode { node: ClusterMapNode; x: number; y: number; width: number; height: number }

export interface ClusterMapLayoutOptions { narrow: boolean }

const WIDE = { cluster: { w: 212, h: 84 }, member: { w: 196, h: 52 }, more: { w: 196, h: 40 }, colGap: 136, rowGap: 18, groupGap: 30, indent: 16, tierGap: 36 };
/** A landscape canvas: the packed map aims for this width-to-height ratio. */
const WIDE_ASPECT = 2;
/** A phone labels only its largest bundles; every bundle still opens its counts on tap. */
export const NARROW_LABELLED_BUNDLES = 8;
const NARROW = { cluster: { w: 168, h: 84 }, member: { w: 168, h: 52 }, more: { w: 168, h: 40 }, colGap: 14, rowGap: 14, tierGap: 54 };

function size(kind: ClusterMapNode["kind"], narrow: boolean) {
  const table = narrow ? NARROW : WIDE;
  return table[kind];
}

/** Groups of one tier, each followed by its shown members and pager, ordered risk first then by barycenter. */
function tierBlocks(view: Pick<ClusterMapResponse, "nodes" | "edges">) {
  const blocks = new Map<number, ClusterMapNode[][]>();
  let current: ClusterMapNode[] | null = null;
  for (const node of view.nodes) {
    if (node.kind === "cluster") {
      current = [node];
      const list = blocks.get(node.tier) ?? [];
      list.push(current);
      blocks.set(node.tier, list);
    } else if (current) current.push(node);
  }
  return blocks;
}

function orderByBarycenter(blocks: Map<number, ClusterMapNode[][]>, edges: ClusterMapEdge[]) {
  const tiers = [...blocks.keys()].sort((a, b) => a - b);
  const rank = new Map<string, number>();
  const weights = new Map<string, { sum: number; weight: number }>();
  const neighbours = new Map<string, Array<[string, number]>>();
  for (const edge of edges) {
    const w = Math.log2(edge.count + 1);
    neighbours.set(edge.source, [...(neighbours.get(edge.source) ?? []), [edge.target, w]]);
    neighbours.set(edge.target, [...(neighbours.get(edge.target) ?? []), [edge.source, w]]);
  }
  const record = () => {
    for (const tier of tiers) blocks.get(tier)!.forEach((block, index) => block.forEach(node => rank.set(node.id, index)));
  };
  record();
  for (const pass of [0, 1]) {
    const sweep = pass === 0 ? tiers : [...tiers].reverse();
    for (const tier of sweep) {
      const list = blocks.get(tier)!;
      for (const block of list) {
        const acc = { sum: 0, weight: 0 };
        for (const node of block) for (const [other, w] of neighbours.get(node.id) ?? []) {
          const r = rank.get(other);
          if (r !== undefined) { acc.sum += r * w; acc.weight += w; }
        }
        weights.set(block[0]!.id, acc);
      }
      const centre = (block: ClusterMapNode[]) => { const acc = weights.get(block[0]!.id)!; return acc.weight ? acc.sum / acc.weight : Number.POSITIVE_INFINITY; };
      const original = new Map(list.map((block, index) => [block[0]!.id, index]));
      list.sort((a, b) => Number(Boolean(b[0]!.risky)) - Number(Boolean(a[0]!.risky)) || centre(a) - centre(b) || original.get(a[0]!.id)! - original.get(b[0]!.id)!);
      record();
    }
  }
  return tiers;
}

function blockHeight(block: ClusterMapNode[]): number {
  return block.reduce((sum, node) => sum + size(node.kind, false).h + WIDE.rowGap, 0) + WIDE.groupGap - WIDE.rowGap;
}

/**
 * Consecutive tiers share a column until the map's width-to-height ratio
 * approaches a landscape frame's, so a sparse estate is not eight thin columns
 * drawn at a third of their size. Tier order is kept left to right, top to bottom.
 */
export function packTiers(tiers: number[], blocks: Map<number, ClusterMapNode[][]>, aspect = WIDE_ASPECT): number[][] {
  const heights = tiers.map(tier => blocks.get(tier)!.reduce((sum, block) => sum + blockHeight(block), 0));
  const total = heights.reduce((sum, h) => sum + h + WIDE.tierGap, 0);
  const columnWidth = WIDE.cluster.w + WIDE.colGap;
  const target = Math.max(1, Math.min(tiers.length, Math.round(Math.sqrt((total * aspect) / columnWidth))));
  const capacity = Math.max(total / target, Math.max(...heights, 0));
  const columns: number[][] = [];
  let current: number[] = [];
  let used = 0;
  tiers.forEach((tier, index) => {
    const h = heights[index]! + WIDE.tierGap;
    if (current.length && used + h > capacity * 1.05 && columns.length < target - 1) { columns.push(current); current = []; used = 0; }
    current.push(tier);
    used += h;
  });
  if (current.length) columns.push(current);
  return columns;
}

export type HandleSide = "l" | "r" | "t" | "b";

/** The sides a bundle leaves and enters by: facing sides across columns, top and bottom within one. */
export function bundleHandles(source: PlacedClusterNode | undefined, target: PlacedClusterNode | undefined, narrow: boolean): { sourceHandle: HandleSide; targetHandle: HandleSide } {
  if (!source || !target) return narrow ? { sourceHandle: "b", targetHandle: "t" } : { sourceHandle: "r", targetHandle: "l" };
  const sameColumn = Math.abs(source.x - target.x) < Math.max(source.width, target.width);
  // Within one column, a bundle that would pass behind other cards bows out to the side instead.
  const adjacent = Math.abs(target.y - source.y) <= Math.max(source.height, target.height) + WIDE.groupGap + WIDE.tierGap;
  if (sameColumn && !narrow && !adjacent) return { sourceHandle: "r", targetHandle: "r" };
  if (narrow || sameColumn) return target.y >= source.y ? { sourceHandle: "b", targetHandle: "t" } : { sourceHandle: "t", targetHandle: "b" };
  return target.x > source.x ? { sourceHandle: "r", targetHandle: "l" } : { sourceHandle: "l", targetHandle: "r" };
}

/** Positions for every drawn card; deterministic for the same response and width class. */
export function clusterMapLayout(view: Pick<ClusterMapResponse, "nodes" | "edges">, { narrow }: ClusterMapLayoutOptions): PlacedClusterNode[] {
  const blocks = tierBlocks(view);
  const tiers = orderByBarycenter(blocks, view.edges);
  const placed: PlacedClusterNode[] = [];
  if (!narrow) {
    for (const [column, columnTiers] of packTiers(tiers, blocks).entries()) {
      let y = 0;
      const x = column * (WIDE.cluster.w + WIDE.colGap);
      for (const [index, tier] of columnTiers.entries()) {
        if (index > 0) y += WIDE.tierGap;
        for (const block of blocks.get(tier)!) {
          for (const node of block) {
            const { w, h } = size(node.kind, false);
            placed.push({ node, x: node.kind === "cluster" ? x : x + WIDE.indent, y, width: w, height: h });
            y += h + WIDE.rowGap;
          }
          y += WIDE.groupGap - WIDE.rowGap;
        }
      }
    }
    return placed;
  }
  // Phone: tiers stack top to bottom, two cards per line, members following their group.
  let y = 0;
  for (const tier of tiers) {
    const cells = blocks.get(tier)!.flat();
    for (let i = 0; i < cells.length; i += 2) {
      const line = cells.slice(i, i + 2);
      const height = Math.max(...line.map(node => size(node.kind, true).h));
      line.forEach((node, j) => placed.push({ node, x: j * (NARROW.cluster.w + NARROW.colGap), y, width: NARROW.cluster.w, height: size(node.kind, true).h }));
      y += height + NARROW.rowGap;
    }
    y += NARROW.tierGap - NARROW.rowGap;
  }
  return placed;
}

export interface ClusterMapGateInput {
  hasScan: boolean;
  /** `?grouping=off`: the operator asked for every edge. */
  groupingOff: boolean;
  /** The grouped read failed for this snapshot; the ungrouped map stands in. */
  unavailable: boolean;
  /** A focused surface (investigation, attack path, scenario, reachability, blast radius) owns the canvas. */
  focusedSurface: boolean;
  /** The containment scope navigation owns the canvas. */
  scopeNavigation: boolean;
  /** The bounded connection preview is on screen (not yet expanded to the full map). */
  previewing: boolean;
  /** Nodes plus edges the ungrouped map would draw. */
  elements: number;
  webgl: boolean;
}

/** The grouped map replaces the ungrouped full map whenever that map would draw more than one frame's budget. */
export function clusterMapEligible(input: ClusterMapGateInput): boolean {
  if (!input.hasScan || input.groupingOff || input.unavailable) return false;
  if (input.focusedSurface || input.scopeNavigation || input.previewing) return false;
  return input.webgl || input.elements > CLUSTER_MAP_ELEMENT_BUDGET;
}

export function severityWords(node: Pick<ClusterMapNode, "worst_severity" | "severity">): string {
  const word = node.worst_severity ?? node.severity ?? "none";
  return word === "none" || word === "info" ? "No critical or high findings" : `Worst ${word}`;
}
