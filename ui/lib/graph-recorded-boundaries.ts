import type { UnifiedGraphData } from "@/lib/graph-schema";

type Box = { id: string; x: number; y: number; width: number; height: number };
export type RecordedBoundary = Box & { label: string; kind: string; members: string[]; contextMembers: string[] };
const SCOPES = new Set(["provider", "account", "organization", "environment", "cluster", "namespace"]);

/** Display associations only: shared normalized entities do not establish exclusive physical placement. */
export function recordedBoundaries(graph: Pick<UnifiedGraphData, "nodes" | "edges">, visible: Box[]): RecordedBoundary[] {
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  const children = new Map<string, Set<string>>(), parents = new Map<string, Set<string>>();
  for (const edge of graph.edges) {
    const source = nodes.get(edge.source), target = nodes.get(edge.target);
    const localUse = edge.relationship === "uses" && source?.entity_type === "agent" && target?.attributes.transport === "stdio";
    const component = edge.relationship === "depends_on" && target?.entity_type === "package";
    const capability = ["provides_tool", "exposes_cred"].includes(edge.relationship) && source?.entity_type === "server";
    if (!["hosts", "hosted_on", "contains"].includes(edge.relationship) && !localUse && !component && !capability) continue;
    const [parent, child] = edge.relationship === "hosted_on" ? [edge.target, edge.source] : [edge.source, edge.target];
    if (!children.has(parent)) children.set(parent, new Set());
    if (!parents.has(child)) parents.set(child, new Set());
    children.get(parent)!.add(child); parents.get(child)!.add(parent);
  }
  const scopes = graph.nodes.filter(node => SCOPES.has(node.entity_type)).map(node => {
    const descendants = new Set<string>(), queue = [...(children.get(node.id) ?? [])];
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i]!;
      if (id === node.id || descendants.has(id)) continue;
      descendants.add(id); queue.push(...(children.get(id) ?? []));
    }
    const context = new Set([...descendants].filter(id => [...(parents.get(id) ?? [])].some(parent => parent !== node.id && !descendants.has(parent))));
    const pending = [...context];
    for (let i = 0; i < pending.length; i++) for (const child of children.get(pending[i]!) ?? []) {
      if (!context.has(child)) { context.add(child); pending.push(child); }
    }
    return { node, descendants, context, boxes: visible.filter(box => descendants.has(box.id)), labels: [node.label] };
  }).filter(scope => scope.boxes.length).sort((a, b) => b.descendants.size - a.descendants.size || a.node.id.localeCompare(b.node.id));
  const collapsed: typeof scopes = [];
  for (const scope of scopes) {
    const ancestor = collapsed.find(other => other.descendants.has(scope.node.id)
      && other.boxes.length === scope.boxes.length && other.boxes.every(box => scope.boxes.some(member => member.id === box.id)));
    if (ancestor) ancestor.labels.push(scope.node.label);
    else collapsed.push(scope);
  }
  return collapsed.map(scope => {
    const nested = collapsed.filter(other => other !== scope && scope.descendants.has(other.node.id)).length;
    const side = 24 + nested * 12, top = 34 + nested * 32;
    const x = Math.min(...scope.boxes.map(box => box.x)) - side;
    const y = Math.min(...scope.boxes.map(box => box.y)) - top;
    const frame = {id: scope.node.id, label: scope.labels.join(" › "), kind: scope.node.entity_type,
      members: scope.boxes.map(box => box.id), contextMembers: scope.boxes.filter(box => scope.context.has(box.id)).map(box => box.id), x, y,
      width: Math.max(...scope.boxes.map(box => box.x + box.width)) + side - x,
      height: Math.max(...scope.boxes.map(box => box.y + box.height)) + side - y};
    return frame;
  });
}

/** The outermost recorded scope of the visible entities, as one "account › environment › cluster" line. */
export function scopeBreadcrumb(graph: Pick<UnifiedGraphData, "nodes" | "edges">, ids: string[]): string | null {
  return recordedBoundaries(graph, ids.map(id => ({id, x: 0, y: 0, width: 0, height: 0})))[0]?.label ?? null;
}
