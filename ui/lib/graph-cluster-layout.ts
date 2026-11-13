/**
 * Where the grouped map's cards sit, and which bundles it draws between them.
 *
 * Wide screens: one column per tier, in the order of reach (scope, agents,
 * MCP servers and tools, packages, findings, identities and credentials,
 * cloud and data). When the columns are wider than the canvas they wrap into
 * bands stacked top to bottom, so the whole overview fits without panning.
 * Groups inside a column are ordered by a two-sweep barycenter pass seeded by
 * the server's risk order. A phone stacks every card in one column. An
 * expanded group is framed and its bundles meet the frame, except for the
 * member being pointed at.
 */
import type { Box, RouteBand, RouteCard } from "@/lib/graph-cluster-routes";
import type { ClusterMapEdge, ClusterMapNode, ClusterMapResponse } from "@/lib/graph-cluster-map";

export interface PlacedClusterNode extends Box { node: ClusterMapNode; column: number; band: number; slot: number }
export interface ClusterFrame extends Box { id: string; clusterId: string; column: number; band: number; slot: number }
export interface ClusterLayout { cards: PlacedClusterNode[]; frames: ClusterFrame[]; bands: RouteBand[] }
export interface DisplayBundle {
  id: string; source: string; target: string; count: number; relationships: ClusterMapEdge["relationships"]; member: boolean; path: boolean;
}

const WIDE = { cluster: { w: 204, h: 56 }, member: { w: 188, h: 44 }, more: { w: 188, h: 36 }, gap: 112, rowGap: 10, groupGap: 14, bandGap: 64, indent: 8, pad: 6 };
const NARROW = { cluster: { w: 260, h: 56 }, member: { w: 244, h: 44 }, more: { w: 244, h: 36 }, rowGap: 10, groupGap: 14, tierGap: 30, indent: 8, pad: 6 };
/** Layout width the overview wraps to when the canvas width is not known yet. */
export const DEFAULT_LAYOUT_WIDTH = 1200;

export const frameId = (clusterId: string) => `@frame:${clusterId.replace(/^@group:/, "")}`;

type Block = ClusterMapNode[];

function tierBlocks(nodes: ClusterMapNode[]): Map<number, Block[]> {
  const blocks = new Map<number, Block[]>();
  let current: Block | null = null;
  for (const node of nodes) {
    if (node.kind === "cluster") {
      current = [node];
      blocks.set(node.tier, [...(blocks.get(node.tier) ?? []), current]);
    } else if (current) current.push(node);
  }
  return blocks;
}

/** Two barycenter sweeps (left to right, then back) over block order inside each column. */
function orderByBarycenter(blocks: Map<number, Block[]>, edges: ClusterMapEdge[]): number[] {
  const tiers = [...blocks.keys()].sort((a, b) => a - b);
  const neighbours = new Map<string, Array<[string, number]>>();
  for (const edge of edges) {
    const w = Math.log2(edge.count + 1);
    neighbours.set(edge.source, [...(neighbours.get(edge.source) ?? []), [edge.target, w]]);
    neighbours.set(edge.target, [...(neighbours.get(edge.target) ?? []), [edge.source, w]]);
  }
  const rank = new Map<string, number>();
  const record = () => tiers.forEach(tier => blocks.get(tier)!.forEach((block, index) => block.forEach(node => rank.set(node.id, index))));
  record();
  for (const sweep of [tiers, [...tiers].reverse()]) {
    for (const tier of sweep) {
      const list = blocks.get(tier)!;
      const original = new Map(list.map((block, index) => [block[0]!.id, index]));
      const centre = (block: Block) => {
        let sum = 0, weight = 0;
        for (const node of block) for (const [other, w] of neighbours.get(node.id) ?? []) {
          const r = rank.get(other);
          if (r !== undefined && !block.some(item => item.id === other)) { sum += r * w; weight += w; }
        }
        return weight ? sum / weight : original.get(block[0]!.id)!;
      };
      const centres = new Map(list.map(block => [block[0]!.id, centre(block)]));
      list.sort((a, b) => centres.get(a[0]!.id)! - centres.get(b[0]!.id)! || original.get(a[0]!.id)! - original.get(b[0]!.id)!);
      record();
    }
  }
  return tiers;
}

function frameOf(block: Block, placed: PlacedClusterNode[], pad: number): ClusterFrame | null {
  if (!block[0]?.expanded || block.length < 2) return null;
  const items = placed.filter(item => block.some(node => node.id === item.node.id));
  const x = Math.min(...items.map(item => item.x)) - pad, y = Math.min(...items.map(item => item.y)) - pad;
  const width = Math.max(...items.map(item => item.x + item.width)) + pad - x, height = Math.max(...items.map(item => item.y + item.height)) + pad - y;
  const first = items[0]!;
  return { id: frameId(block[0].id), clusterId: block[0].id, column: first.column, band: first.band, slot: first.slot, x, y, width, height };
}

/** Columns per band so that a band is at most `width` wide. */
export function columnsPerBand(columns: number, width: number): number {
  const fit = Math.max(1, Math.floor((width + WIDE.gap) / (WIDE.cluster.w + WIDE.gap)));
  const bands = Math.ceil(columns / fit);
  return Math.ceil(columns / Math.max(bands, 1));
}

/** Positions for every drawn card and frame; deterministic for the same response, width class and width. */
export function clusterMapLayout(view: Pick<ClusterMapResponse, "nodes" | "edges">, { narrow, width = DEFAULT_LAYOUT_WIDTH }: { narrow: boolean; width?: number }): ClusterLayout {
  const blocks = tierBlocks(view.nodes);
  const tiers = orderByBarycenter(blocks, view.edges);
  const cards: PlacedClusterNode[] = [];
  const frames: ClusterFrame[] = [];
  const bands: RouteBand[] = [];
  const s = narrow ? NARROW : WIDE;
  const perBand = narrow ? tiers.length : columnsPerBand(tiers.length, width);
  let top = 0, y = 0;
  tiers.forEach((tier, column) => {
    const band = narrow ? 0 : Math.floor(column / perBand);
    const slot = narrow ? 0 : column % perBand;
    if (!narrow && slot === 0) {
      if (column > 0) { bands.push({ top, bottom: Math.max(...cards.filter(c => c.band === band - 1).map(c => c.y + c.height), ...frames.filter(f => f.band === band - 1).map(f => f.y + f.height)) }); top = bands.at(-1)!.bottom + WIDE.bandGap; }
    }
    const x = narrow ? 0 : slot * (WIDE.cluster.w + WIDE.gap);
    if (!narrow) y = top;
    for (const block of blocks.get(tier)!) {
      const framed = Boolean(block[0]?.expanded) && block.length > 1;
      if (framed) y += s.pad;
      for (const node of block) {
        const { w, h } = s[node.kind];
        cards.push({ node, column, band, slot, x: node.kind === "cluster" ? x : x + s.indent, y, width: w, height: h });
        y += h + s.rowGap;
      }
      const frame = frameOf(block, cards, s.pad);
      if (frame) frames.push(frame);
      y += s.groupGap - s.rowGap + (framed ? s.pad : 0);
    }
    if (narrow) y += NARROW.tierGap;
  });
  const lastBand = narrow ? 0 : Math.floor((tiers.length - 1) / perBand);
  const inLast = [...cards.filter(c => c.band === lastBand), ...frames.filter(f => f.band === lastBand)];
  if (inLast.length) bands.push({ top: narrow ? 0 : top, bottom: Math.max(...inLast.map(item => item.y + item.height)) });
  return { cards, frames, bands };
}

/**
 * The bundles to draw: an expanded group's member and pager bundles merge into
 * one bundle on its frame, except the active member's own, which are drawn
 * from the member and taken out of the frame's count so every count stays exact.
 */
export function displayBundles(view: Pick<ClusterMapResponse, "nodes" | "edges">, activeMember: string | null): DisplayBundle[] {
  const owner = new Map<string, string>();
  for (const node of view.nodes) if ((node.kind === "member" || node.kind === "more") && node.cluster_id) owner.set(node.id, frameId(node.cluster_id));
  const merged = new Map<string, DisplayBundle>();
  for (const edge of view.edges) {
    const keep = (id: string) => (id === activeMember ? id : owner.get(id) ?? id);
    const source = keep(edge.source), target = keep(edge.target);
    if (source === target) continue;
    if ((source === activeMember && owner.get(activeMember) === target) || (target === activeMember && owner.get(activeMember) === source)) continue;
    const id = `${source}->${target}`;
    const path = Boolean(edge.on_attack_path);
    const current = merged.get(id);
    if (!current) {
      merged.set(id, { id, source, target, count: edge.count, relationships: edge.relationships.map(item => ({ ...item })), member: source === activeMember || target === activeMember, path });
      continue;
    }
    current.count += edge.count;
    current.path ||= path;
    for (const item of edge.relationships) {
      const existing = current.relationships.find(rel => rel.relationship === item.relationship);
      if (existing) existing.count += item.count; else current.relationships.push({ ...item });
    }
    current.relationships.sort((a, b) => b.count - a.count || a.relationship.localeCompare(b.relationship));
  }
  return [...merged.values()].sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
}

/** What the router connects: frames stand in for their members, except the active member. */
export function routeCards(layout: ClusterLayout, activeMember: string | null): RouteCard[] {
  const framed = new Set(layout.frames.map(frame => frame.clusterId));
  const cards: RouteCard[] = layout.cards
    .filter(item => item.node.kind === "cluster" ? !framed.has(item.node.id) : !(item.node.cluster_id && framed.has(item.node.cluster_id)) || item.node.id === activeMember)
    .map(item => ({ id: item.node.id, column: item.column, band: item.band, slot: item.slot, x: item.x, y: item.y, width: item.width, height: item.height }));
  return [...cards, ...layout.frames.map(frame => ({ id: frame.id, column: frame.column, band: frame.band, slot: frame.slot, x: frame.x, y: frame.y, width: frame.width, height: frame.height }))];
}

/**
 * The overview draws what reads at a glance: bundles between adjacent columns
 * and every bundle that carries an attack-path hop. The rest stay hidden until
 * a group they touch is pointed at or "Show all links" is on, and are counted.
 */
export function overviewBundles(bundles: DisplayBundle[], cards: RouteCard[], { showAll, focusIds }: { showAll: boolean; focusIds: readonly string[] }) {
  if (showAll) return { shown: bundles, hidden: [] as DisplayBundle[] };
  const column = new Map(cards.map(card => [card.id, card.column]));
  const focus = new Set(focusIds);
  const shown: DisplayBundle[] = [], hidden: DisplayBundle[] = [];
  for (const bundle of bundles) {
    const a = column.get(bundle.source), b = column.get(bundle.target);
    const adjacent = a !== undefined && b !== undefined && Math.abs(a - b) === 1;
    (adjacent || bundle.path || focus.has(bundle.source) || focus.has(bundle.target) ? shown : hidden).push(bundle);
  }
  return { shown, hidden };
}
