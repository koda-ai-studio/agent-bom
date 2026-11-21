/** Vertical spacing between parallel relationship lanes that leave or enter one port. */
export const LANE_GAP = 14;

export type LaneEdge = {
  id: string;
  source: string;
  target: string;
  sourceHandle?: string | null | undefined;
  targetHandle?: string | null | undefined;
  hidden?: boolean | undefined;
  data?: Record<string, unknown> | undefined;
};

/**
 * `source` and `target` shift a line off its port's centre row; `channel` is the
 * index offset of its target among the targets fed across the same column gap,
 * out of `channels`, so each target turns at its own column.
 */
export type RelationshipLane = { source: number; target: number; channel?: number; channels?: number };


/**
 * The card side an edge end attaches to. A backward edge leaves its source's
 * left `context` handle and enters its target's right `context` handle, so it
 * shares a side with the forward edges at the other end of that card.
 */
function cardSide(edge: LaneEdge, side: "source" | "target"): string {
  const handle = (side === "source" ? edge.sourceHandle : edge.targetHandle) ?? null;
  if (handle === "context") return side === "source" ? "left" : "right";
  if (handle === null) return side === "source" ? "right" : "left";
  return `${side}:${handle}`;
}

/**
 * Offset of this edge's relationship type among the types meeting one side of a
 * card, whether they leave or enter it. Every edge owns a port offset, ordered by its far endpoint; two sources
 * never share an incoming segment even when their relationship kinds match.
 */
function portOffset(edge: LaneEdge, edges: LaneEdge[], side: "source" | "target", yOf: (id: string) => number | undefined): number {
  const node = edge[side];
  const at = cardSide(edge, side);
  const groups = new Map<string, number[]>();
  for (const item of edges) {
    if (item.hidden) continue;
    for (const end of ["source", "target"] as const) {
      if (item[end] !== node || cardSide(item, end) !== at) continue;
      const y = yOf(item[end === "source" ? "target" : "source"]);
      const ys = groups.get(item.id) ?? [];
      if (y !== undefined) ys.push(y);
      groups.set(item.id, ys);
    }
  }
  if (groups.size < 2) return 0;
  const mean = (ys: number[]) => ys.length ? ys.reduce((sum, y) => sum + y, 0) / ys.length : 0;
  const order = [...groups].sort(([a, ay], [b, by]) => mean(ay) - mean(by) || a.localeCompare(b)).map(([name]) => name);
  return (order.indexOf(edge.id) - (order.length - 1) / 2) * LANE_GAP;
}

const netKey = (edge: LaneEdge) => `${edge.source}\u0000${edge.target}\u0000${edge.targetHandle ?? ""}`;

/**
 * Lines crossing one column gap toward different targets each turn in their own
 * channel, so a shared vertical never joins sources to the wrong target. A target
 * fed from above takes a channel nearer its sources the lower it sits, and one fed
 * from below the higher it sits, so the channels nest instead of crossing.
 */
function channelOf(edge: LaneEdge, edges: LaneEdge[], yOf: (id: string) => number | undefined, xOf: (id: string) => number | undefined) {
  const sourceX = xOf(edge.source), targetX = xOf(edge.target);
  if (sourceX === undefined || targetX === undefined || targetX <= sourceX) return { channel: 0, channels: 1 };
  const nets = new Map<string, { targetY: number; sourceYs: number[] }>();
  for (const item of edges) {
    if (item.hidden || xOf(item.source) !== sourceX || xOf(item.target) !== targetX) continue;
    const targetY = yOf(item.target), sourceY = yOf(item.source);
    if (targetY === undefined || sourceY === undefined) continue;
    const net = nets.get(netKey(item)) ?? { targetY, sourceYs: [] };
    net.sourceYs.push(sourceY);
    nets.set(netKey(item), net);
  }
  if (nets.size < 2) return { channel: 0, channels: 1 };
  const order = [...nets].map(([key, net]) => {
    const mean = net.sourceYs.reduce((sum, y) => sum + y, 0) / net.sourceYs.length;
    return { key, rank: net.targetY >= mean ? -net.targetY : net.targetY };
  }).sort((a, b) => a.rank - b.rank || a.key.localeCompare(b.key)).map(item => item.key);
  const index = order.indexOf(netKey(edge));
  return index < 0 ? { channel: 0, channels: 1 } : { channel: index - (order.length - 1) / 2, channels: order.length };
}

export function relationshipLaneFor(
  edgeId: string, edges: LaneEdge[], yOf: (id: string) => number | undefined, xOf?: (id: string) => number | undefined,
): RelationshipLane {
  const edge = edges.find(item => item.id === edgeId);
  if (!edge || edge.hidden) return { source: 0, target: 0 };
  const lane = { source: portOffset(edge, edges, "source", yOf), target: portOffset(edge, edges, "target", yOf) };
  if (!xOf) return lane;
  const { channel, channels } = channelOf(edge, edges, yOf, xOf);
  return channel ? { ...lane, channel, channels } : lane;
}
