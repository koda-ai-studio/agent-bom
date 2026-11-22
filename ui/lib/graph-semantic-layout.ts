import { assetKindLabel, assetServiceLabel } from "@/lib/asset-icon-registry";
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
      if (edge.target === node.id && (["contains", "vulnerable_to", "exhibits_drift"].includes(kind) || kind === "depends_on" && semanticLayer(node) === "package")) return [edge.source];
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
  const byId = new Map(nodes.map(node => [node.id, node]));
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
  const rowHeight = (id: string) => owners.has(id) ? 132 : 216;
  const occupied = new Map<number, { y: number; height: number }[]>();
  const place = (id: string, desired: number) => {
    const column = columns.get(id)!;
    const used = occupied.get(column) ?? [];
    const height = rowHeight(id), gap = height + 24;
    const choices = [desired];
    for (let step = 1; step <= nodes.length; step++) choices.push(desired + step * gap, desired - step * gap);
    const y = choices.find(value => (!primary.length || value >= 0) && used.every(other => value >= other.y + other.height + 24 || value + height + 24 <= other.y)) ?? desired;
    occupied.set(column, [...used, { y, height }]); positions.set(id, { x: column * SEMANTIC_COLUMN_GAP, y });
  };
  const placeOwned = (id: string) => {
    for (const child of [...owners.keys()].sort()) {
      if (owners.get(child) !== id || positions.has(child)) continue;
      place(child, positions.get(id)!.y + rowHeight(id) + 24);
      placeOwned(child);
    }
  };
  for (const id of primary) if (columns.has(id)) { place(id, 0); placeOwned(id); }
  const pending = visible.filter(node => !onPath.has(node.id)).sort((a, b) => columns.get(a.id)! - columns.get(b.id)! || a.id.localeCompare(b.id));
  const siblings = new Map<number, Node<LineageNodeData>[]>();
  for (const node of pending) if (!owners.has(node.id)) {
    const column = columns.get(node.id)!;
    siblings.set(column, [...(siblings.get(column) ?? []), node]);
  }
  for (const members of siblings.values()) {
    const parentRows = members.flatMap(node => edges.filter(edge => edge.target === node.id).flatMap(edge => {
      const parent = positions.get(edge.source);
      return parent ? [parent.y] : [];
    }));
    const center = parentRows.length ? parentRows.reduce((sum, y) => sum + y, 0) / parentRows.length : 0;
    members.forEach((node, index) => {
      place(node.id, primary.length ? SEMANTIC_ROW_GAP * (index + 1)
        : center + SEMANTIC_ROW_GAP * (index - (members.length - 1) / 2));
      placeOwned(node.id);
    });
  }
  const owned = pending.filter(node => owners.has(node.id));
  for (let pass = 0; pass < owned.length; pass++) for (const node of owned) {
    if (positions.has(node.id)) continue;
    const owner = positions.get(owners.get(node.id)!);
    if (owner) place(node.id, owner.y + rowHeight(owners.get(node.id)!) + 24);
  }
  for (const node of owned) if (!positions.has(node.id)) place(node.id, SEMANTIC_ROW_GAP);
  const pathPairs = new Set(primary.slice(1).map((id, index) => `${primary[index]}\u0000${id}`));
  return {
    nodes: nodes.map(node => ({ ...node, position: positions.get(node.id) ?? node.position,
      style: { ...node.style, width: 300, minHeight: rowHeight(node.id), "--graph-node-card-width": "300px" },
      data: { ...node.data, evidenceFlow: true, semanticLayout: true,
        ...(onPath.has(node.id) ? { semanticPathIndex: primary.indexOf(node.id) } : {}), renderBand: "detail" as const,
        readingLabel: node.data.readingLabel ?? assetServiceLabel({ nodeType: node.data.nodeType, entityType: node.data.entityType, attributes: node.data.attributes, provider: node.data.dimensions?.cloud_provider }) ?? assetKindLabel({ nodeType: node.data.nodeType, entityType: node.data.entityType, attributes: node.data.attributes }),
        readingFinding: semanticLayer(node) === "finding",
        evidenceFlowContext: node.data.evidenceFlowContext ?? (semanticLayer(node) === "mcp_server" ? (() => {
          const clients = [...new Set(edges.filter(edge => edge.target === node.id && edge.data?.relationship === "uses"
            && byId.get(edge.source)?.data.semanticLayer === "orchestration").map(edge => byId.get(edge.source)!.data.label))].sort();
          return clients.length ? `Client: ${clients.join(", ")}` : "Client link not recorded";
        })() : undefined), semanticOwner: owners.get(node.id), readingOwner: semanticLayer(node) === "finding" ? owners.get(node.id) : undefined,
        imageSubrow: images.owners.has(node.id) && !onPath.has(node.id), evidenceSources: images.sources.get(node.id),
        semanticLayerIssue: semanticLayer(node) === null ? "Semantic layer unavailable" : undefined,
        highlighted: node.data.highlighted || onPath.has(node.id) } })),
    edges: edges.map((edge): Edge => {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      const reverse = from && to && from.x > to.x;
      const sameColumn = from && to && from.x === to.x;
      return { ...edge, type: "relationship", sourceHandle: reverse ? "context" : null, targetHandle: reverse || sameColumn ? "context" : null,
        data: { ...edge.data, semanticLayout: true, individualLabel: true, directionEmphasis: true, quietLabel: edge.data?.isClusterEdge !== true,
          pathEmphasis: pathPairs.has(`${edge.source}\u0000${edge.target}`) || edge.data?.pathEmphasis === true } };
    }),
  };
}
