import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

const SEVERITY: Record<string, number> = { critical:0, high:1, medium:2, low:3 };
const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);

/** A bounded, recorded endpoint/MCP/identity branch. Categories do not imply
 * connectivity. Cycles, crowded ranks and rollups retain the general layout. */
export function mixedEvidenceFlow(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  if (nodes.length > 24 || edges.length > 32 || !nodes.some(n => n.data.nodeType === "server")
    || !nodes.some(n => n.data.nodeType === "apiGateway") || nodes.some(n => n.data.rollup || n.type === "clusterPillNode")) return null;
  const all = new Map(nodes.map(n => [n.id, n]));
  const visible = nodes.filter(n => !n.hidden);
  const ids = new Set(visible.map(n => n.id));
  const reverse = (e: Edge) => (e.data?.relationship === "affects" && FINDINGS.has(all.get(e.source)?.data.nodeType ?? ""))
    || ["hosted_on", "part_of", "belongs_to"].includes(String(e.data?.relationship));
  const links = edges.filter(e => !e.hidden && ids.has(e.source) && ids.has(e.target)
    && !["correlates_with", "associated_with"].includes(String(e.data?.relationship)))
    .map(e => reverse(e) ? { source: e.target, target: e.source } : e);
  const parents = new Map(visible.map(n => [n.id, [...new Set(links.filter(e => e.target === n.id).map(e => e.source))].sort()]));
  const ranks = new Map<string, number>(), chains = new Map<string, string[]>();
  const pending = new Set(ids);
  while (pending.size) {
    const ready = [...pending].filter(id => parents.get(id)!.every(p => ranks.has(p))).sort();
    if (!ready.length) return null;
    for (const id of ready) {
      const paths = parents.get(id)!.map(p => chains.get(p)!).sort((a,b) => b.length-a.length || a.join().localeCompare(b.join()));
      const chain = [...(paths[0] ?? []), id];
      ranks.set(id, chain.length-1); chains.set(id,chain); pending.delete(id);
    }
  }
  const assetChains = visible.filter(n => !FINDINGS.has(n.data.nodeType)).map(n => chains.get(n.id)!)
    .sort((a,b) => b.length-a.length || a.join().localeCompare(b.join()));
  const spine = new Set(assetChains[0] ?? []);
  const positions = new Map<string, { x: number; y: number }>();
  for (const rank of [...new Set(ranks.values())].sort((a,b) => a-b)) {
    const lane = visible.filter(n => ranks.get(n.id) === rank).sort((a,b) => Number(spine.has(b.id))-Number(spine.has(a.id))
      || Number(FINDINGS.has(a.data.nodeType))-Number(FINDINGS.has(b.data.nodeType))
      || (SEVERITY[a.data.severity ?? ""] ?? 4)-(SEVERITY[b.data.severity ?? ""] ?? 4) || a.id.localeCompare(b.id));
    if (lane.length > 4 || rank > 6) return null;
    const occupied: number[] = [];
    for (const n of lane) {
      const upstream = parents.get(n.id)!.map(p => positions.get(p)!.y);
      const desired = spine.has(n.id) || !upstream.length ? 0 : upstream.reduce((a,b) => a+b,0)/upstream.length;
      const choices = [desired];
      for (let step=1; step<=8; step++) choices.push(desired-step*240,desired+step*240);
      const y = choices.find(at => occupied.every(other => Math.abs(other-at)>=240))!;
      occupied.push(y); positions.set(n.id,{ x:rank*400,y });
    }
  }
  const owner = (n: Node<LineageNodeData>) => {
    if (!FINDINGS.has(n.data.nodeType)) return undefined;
    const links = edges.filter(e => e.source === n.id || e.target === n.id);
    if (links.length !== 1) return undefined;
    const e = links[0]!;
    const id = e.source === n.id && e.data?.relationship === "affects" ? e.target
      : e.target === n.id && e.data?.relationship === "vulnerable_to" ? e.source : undefined;
    return id && all.has(id) && !FINDINGS.has(all.get(id)!.data.nodeType) ? id : undefined;
  };
  return {
    nodes: nodes.map(n => ({ ...n, position: positions.get(n.id) ?? n.position,
      style: { ...n.style, width:260, minHeight:188, "--graph-node-card-width":"260px" },
      data: { ...n.data, evidenceFlow:true, readingFinding:FINDINGS.has(n.data.nodeType), readingOwner:owner(n) } })),
    edges: edges.map((e): Edge => ({ ...e, ...(reverse(e) ? { sourceHandle:"context",targetHandle:"context" } : {}),
      data: { ...e.data, mcpEvidenceFlow:true, quietLabel:true, boundedOverview:true, directionEmphasis:true } })),
  };
}
