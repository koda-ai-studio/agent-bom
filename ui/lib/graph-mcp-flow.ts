import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

const LANES: Record<string, number> = { agent: 0, server: 1, sharedServer: 1,
  package: 2, credential: 2, tool: 2, vulnerability: 3, misconfiguration: 3 };
/** Cards render 203-272px tall, so rows are spaced for the tallest one plus a gap; 224px rows let them overlap. */
const CARD_MAX_HEIGHT = 272;
export const MCP_FLOW_FOOTPRINT = { width: 260, height: 188, cardMaxHeight: CARD_MAX_HEIGHT, column: 368, row: CARD_MAX_HEIGHT + 28 };

/** Recorded branches organize a small MCP inventory; they never assert a missing link.
 * Mixed infrastructure and larger estates retain the general hierarchy. */
export function mcpEvidenceFlow(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  if (edges.length > 32 || !nodes.some(n => n.data.nodeType === "agent") || !nodes.some(n => n.data.nodeType === "server")
    || nodes.some(n => n.data.rollup || n.type === "clusterPillNode" || n.hidden || !Object.hasOwn(LANES, n.data.nodeType))) return null;
  const lanes = [0, 1, 2, 3].map(lane => nodes.filter(n => LANES[n.data.nodeType] === lane)
    .sort((a, b) => a.data.label.localeCompare(b.data.label) || a.id.localeCompare(b.id)));
  if (lanes.some(lane => lane.length > 4)) return null;
  const byId = new Map(nodes.map(n => [n.id, n]));
  // Put a recorded evidence chain first. This is a visual priority, not an
  // attack-path assertion; links, direction, evidence tiers and IDs are retained.
  const severity: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
  const findings = [...lanes[3]!].sort((a, b) =>
    ((severity[a.data.severity ?? "none"] ?? 4) - (severity[b.data.severity ?? "none"] ?? 4)) || a.id.localeCompare(b.id));
  const parents = (id: string) => edges.flatMap(e => {
    const [source, target] = e.data?.relationship === "affects" ? [e.target, e.source] : [e.source, e.target];
    return !e.hidden && target === id && byId.has(source) && LANES[byId.get(source)!.data.nodeType]! < LANES[byId.get(id)!.data.nodeType]!
      && !["correlates_with", "associated_with"].includes(String(e.data?.relationship)) ? [source] : [];
  }).sort();
  const chain = (id: string): string[] => {
    const paths = parents(id).map(parent => chain(parent));
    paths.sort((a, b) => b.length - a.length || a.join().localeCompare(b.join()));
    return [...(paths[0] ?? []), id];
  };
  const spine = new Set(findings[0] ? chain(findings[0].id) : []);
  for (const lane of lanes) {
    const primaryLabels = new Set(lane.filter(n => spine.has(n.id)).map(n => n.data.label));
    lane.sort((a, b) => Number(spine.has(b.id)) - Number(spine.has(a.id))
      || Number(parents(b.id).length > 0) - Number(parents(a.id).length > 0)
      || Number(primaryLabels.has(b.data.label)) - Number(primaryLabels.has(a.data.label))
      || a.data.label.localeCompare(b.data.label) || a.id.localeCompare(b.id));
  }
  const rowById = new Map<string, number>();
  for (const lane of lanes) {
    const used: number[] = [];
    for (const n of lane) {
      const upstream = parents(n.id).flatMap(id => rowById.has(id) ? [rowById.get(id)!] : []);
      const desired = spine.has(n.id) ? 0 : upstream.length ? upstream.reduce((a, b) => a + b, 0) / upstream.length : 0;
      // Keep the main chain level and place support on both sides. The old
      // downward-only collision search pushed the chain against the top edge.
      const choices = [desired];
      for (let step = 0.5; step <= 8; step += 0.5) choices.push(desired + step, desired - step);
      const row = choices.find(candidate => used.every(other => Math.abs(other - candidate) >= 1)) ?? desired + 9;
      used.push(row); rowById.set(n.id, row);
    }
  }
  const positions = new Map(nodes.map(n => [n.id, {
    x: LANES[n.data.nodeType]! * MCP_FLOW_FOOTPRINT.column, y: 96 + rowById.get(n.id)! * MCP_FLOW_FOOTPRINT.row,
  }] as const));
  return {
    nodes: nodes.map(n => ({ ...n, position: positions.get(n.id)!,
      style: { ...n.style, width: LANES[n.data.nodeType] === 3 ? 320 : MCP_FLOW_FOOTPRINT.width, minHeight: MCP_FLOW_FOOTPRINT.height, "--graph-node-card-width": LANES[n.data.nodeType] === 3 ? "320px" : "260px" },
      data: { ...n.data, evidenceFlow: true,
        evidenceFlowContext: LANES[n.data.nodeType] === 1 ? (() => {
          const clients = [...new Set(edges.filter(e => e.target === n.id && e.data?.relationship === "uses"
            && byId.get(e.source)?.data.nodeType === "agent").map(e => byId.get(e.source)!.data.label))].sort();
          return clients.length ? `Client: ${clients.join(", ")}` : "Client link not recorded";
        })() : undefined,
      },
    })),
    edges: edges.map((edge): Edge => ({ ...edge,
      // A finding may point back to an affected package; retain that direction.
      ...(LANES[byId.get(edge.source)?.data.nodeType ?? ""]! > LANES[byId.get(edge.target)?.data.nodeType ?? ""]!
        ? { sourceHandle: "context", targetHandle: "context" } : {}),
      data: { ...edge.data, mcpEvidenceFlow: true, quietLabel: true, boundedOverview: true, directionEmphasis: true,
      },
    })),
  };
}

/** Recorded upstream evidence for a finding, including reverse `affects` edges.
 * Associations do not turn unrelated branches into a supporting path. */
export function findingEvidenceContext(id: string, nodes: Node<LineageNodeData>[], edges: Edge[]): Set<string> | null {
  if (!nodes.some(n => n.id === id && n.data.evidenceFlow && ["vulnerability", "misconfiguration"].includes(n.data.nodeType))) return null;
  const visible = new Set(nodes.map(n => n.id));
  const parents = new Map<string, string[]>();
  for (const e of edges) {
    if (e.hidden || !visible.has(e.source) || !visible.has(e.target) || ["correlates_with", "associated_with"].includes(String(e.data?.relationship))) continue;
    const [source, target] = e.data?.relationship === "affects" ? [e.target, e.source] : [e.source, e.target];
    parents.set(target, [...(parents.get(target) ?? []), source]);
  }
  const visited = new Set([id]), queue = [id];
  for (let i = 0; i < queue.length; i++) for (const parent of parents.get(queue[i]!) ?? []) {
    if (!visited.has(parent)) { visited.add(parent); queue.push(parent); }
  }
  return visited;
}
