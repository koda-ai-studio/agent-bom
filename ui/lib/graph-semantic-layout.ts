import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticColumns, semanticLayer } from "@/lib/graph-semantic-columns";
import { INTERNET_ANCHOR_ID, internetExposure, withInternetAnchor } from "@/lib/graph-internet-context";
import { workloadImageContext } from "@/lib/graph-workload-image";

export const SEMANTIC_COLUMN_GAP = 380;
export const SEMANTIC_ROW_GAP = 240;

function contextOwners(nodes: Node<LineageNodeData>[], edges: Edge[], primary: ReadonlySet<string>) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const owners = new Map<string, string>();
  for (const node of nodes) {
    if (primary.has(node.id) || !["package", "finding", "runtime_evidence"].includes(semanticLayer(node) ?? "")) continue;
    if (node.data.readingOwner && byId.has(node.data.readingOwner)) { owners.set(node.id, node.data.readingOwner); continue; }
    const candidates = new Set(edges.flatMap(edge => {
      const kind = String(edge.data?.relationship ?? "");
      if (edge.target === node.id && ["contains", "vulnerable_to", "exhibits_drift"].includes(kind)) return [edge.source];
      if (edge.source === node.id && kind === "affects") return [edge.target];
      return [];
    }).filter(id => id !== node.id));
    if (candidates.size === 1 && byId.has([...candidates][0]!)) owners.set(node.id, [...candidates][0]!);
  }
  return owners;
}

/** One left-to-right grammar for every canvas. The backend's selected path
 * owns row zero. Context remains attached to its recorded owner. */
export function semanticGraphLayout(nodes: Node<LineageNodeData>[], edges: Edge[], selectedPath?: readonly string[]) {
  ({ nodes, edges } = withInternetAnchor(nodes, edges));
  const visible = nodes.filter(node => !node.hidden);
  let primary = selectedPath ?? visible.filter(node => typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex!).map(node => node.id);
  if (primary.length && primary[0] !== INTERNET_ANCHOR_ID
    && internetExposure(visible.find(node => node.id === primary[0])?.data.attributes) === true) primary = [INTERNET_ANCHOR_ID, ...primary];
  const onPath = new Set(primary);
  const columns = semanticColumns(visible, edges.filter(edge => !edge.hidden), primary);
  const owners = contextOwners(visible, edges, onPath);
  const images = workloadImageContext(visible, edges);
  for (const [id, owner] of images.owners) if (!onPath.has(id)) owners.set(id, owner);
  for (const id of owners.keys()) {
    const seen = new Set([id]);
    let owner = owners.get(id)!;
    while (owners.has(owner) && !seen.has(owner)) { seen.add(owner); owner = owners.get(owner)!; }
    if (!seen.has(owner)) columns.set(id, columns.get(owner)!);
  }
  const positions = new Map<string, { x: number; y: number }>();
  const occupied = new Map<number, number[]>();
  const place = (id: string, desired: number) => {
    const column = columns.get(id)!;
    const used = occupied.get(column) ?? [];
    const choices = [desired];
    for (let step = 1; step <= nodes.length; step++) choices.push(desired + step * SEMANTIC_ROW_GAP, desired - step * SEMANTIC_ROW_GAP);
    const y = choices.find(value => used.every(other => Math.abs(other - value) >= SEMANTIC_ROW_GAP)) ?? desired;
    occupied.set(column, [...used, y]); positions.set(id, { x: column * SEMANTIC_COLUMN_GAP, y });
  };
  for (const id of primary) if (columns.has(id)) place(id, 0);
  const pending = visible.filter(node => !onPath.has(node.id)).sort((a, b) => columns.get(a.id)! - columns.get(b.id)! || a.id.localeCompare(b.id));
  const siblings = new Map<number, Node<LineageNodeData>[]>();
  for (const node of pending) if (!owners.has(node.id)) {
    const column = columns.get(node.id)!;
    siblings.set(column, [...(siblings.get(column) ?? []), node]);
  }
  for (const [column, members] of siblings) {
    const parentRows = members.flatMap(node => edges.filter(edge => edge.target === node.id).flatMap(edge => {
      const parent = positions.get(edge.source);
      return parent ? [parent.y] : [];
    }));
    const center = parentRows.length ? parentRows.reduce((sum, y) => sum + y, 0) / parentRows.length : 0;
    const spineHere = occupied.has(column);
    members.forEach((node, index) => place(node.id, center + SEMANTIC_ROW_GAP * (spineHere
      ? (Math.floor(index / 2) + 1) * (index % 2 ? -1 : 1) : index - (members.length - 1) / 2)));
  }
  const owned = pending.filter(node => owners.has(node.id));
  for (let pass = 0; pass < owned.length; pass++) for (const node of owned) {
    if (positions.has(node.id)) continue;
    const owner = positions.get(owners.get(node.id)!);
    if (owner) place(node.id, owner.y + SEMANTIC_ROW_GAP);
  }
  for (const node of owned) if (!positions.has(node.id)) place(node.id, SEMANTIC_ROW_GAP);
  const pathPairs = new Set(primary.slice(1).map((id, index) => `${primary[index]}\u0000${id}`));
  return {
    nodes: nodes.map(node => ({ ...node, position: positions.get(node.id) ?? node.position,
      style: { ...node.style, width: 240, minHeight: 180, "--graph-node-card-width": "240px" },
      data: { ...node.data, evidenceFlow: true, semanticLayout: true, semanticOwner: owners.get(node.id), readingOwner: semanticLayer(node) === "finding" ? owners.get(node.id) : undefined,
        imageSubrow: images.owners.has(node.id) && !onPath.has(node.id), evidenceSources: images.sources.get(node.id),
        semanticLayerIssue: semanticLayer(node) === null ? "Semantic layer unavailable" : undefined,
        highlighted: node.data.highlighted || onPath.has(node.id) } })),
    edges: edges.map((edge): Edge => {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      const reverse = from && to && from.x > to.x;
      return { ...edge, type: "relationship", ...(reverse ? { sourceHandle: "context", targetHandle: "context" } : {}),
        data: { ...edge.data, semanticLayout: true, individualLabel: true, directionEmphasis: true,
          pathEmphasis: pathPairs.has(`${edge.source}\u0000${edge.target}`) || edge.data?.pathEmphasis === true } };
    }),
  };
}
