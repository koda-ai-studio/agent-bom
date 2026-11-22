import { assetKindLabel, assetServiceLabel } from "@/lib/asset-icon-registry";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticColumns, semanticLayer } from "@/lib/graph-semantic-columns";
import { INTERNET_ANCHOR_ID, internetExposure, withInternetAnchor } from "@/lib/graph-internet-context";
import { workloadImageContext } from "@/lib/graph-workload-image";
import { edgeFamily, edgeFamilyColor } from "@/lib/graph-edge-family";
import { COMPACT_NODE_WIDTH, COMPACT_RANK_GAP, COMPACT_ROW_GAP, compactLayout } from "@/lib/graph-compact-layout";

export const SEMANTIC_COLUMN_GAP = COMPACT_RANK_GAP;
export const SEMANTIC_ROW_GAP = COMPACT_ROW_GAP;

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

/** Display nodes drawn beside another node's rank rather than in a backend column. */
function attachedRanks(visible: Node<LineageNodeData>[], edges: Edge[]) {
  const ids = new Set(visible.map(node => node.id));
  const attached = new Map<string, { to: string; offset: number }>();
  const exposed = edges.filter(edge => edge.source === INTERNET_ANCHOR_ID && ids.has(edge.target)).map(edge => edge.target);
  if (ids.has(INTERNET_ANCHOR_ID) && exposed.length) attached.set(INTERNET_ANCHOR_ID, { to: exposed.join("\n"), offset: -0.5 });
  for (const node of visible) {
    const owner = node.data.displayTargetId;
    if (node.type === "findingGroupNode" && node.data.displayOnly && owner && ids.has(owner)) attached.set(node.id, { to: owner, offset: 0.5 });
  }
  return attached;
}

/** One left-to-right grammar for every canvas. The backend's selected path
 * owns row zero; every other branch fans around the nodes it connects to. */
export function semanticGraphLayout(nodes: Node<LineageNodeData>[], edges: Edge[], selectedPath?: readonly string[]) {
  ({ nodes, edges } = withInternetAnchor(nodes, edges));
  const visible = nodes.filter(node => !node.hidden);
  const byId = new Map(nodes.map(node => [node.id, node]));
  let primary = selectedPath ?? visible.filter(node => typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex!).map(node => node.id);
  if (primary.length && primary[0] !== INTERNET_ANCHOR_ID
    && internetExposure(visible.find(node => node.id === primary[0])?.data.attributes) === true) primary = [INTERNET_ANCHOR_ID, ...primary];
  const onPath = new Set(primary);
  const drawn = edges.filter(edge => !edge.hidden);
  const columns = semanticColumns(visible, drawn, primary);
  const owners = contextOwners(visible, edges, onPath);
  const images = workloadImageContext(visible, edges);
  for (const [id, owner] of images.owners) if (!onPath.has(id)) owners.set(id, owner);
  const { positions, lanes } = compactLayout({ ids: visible.map(node => node.id), links: drawn, column: id => columns.get(id) ?? 0,
    spine: primary, attached: attachedRanks(visible, drawn) });
  const pathPairs = new Set(primary.slice(1).map((id, index) => `${primary[index]}\u0000${id}`));
  return {
    nodes: nodes.map(node => ({ ...node, position: positions.get(node.id) ?? node.position,
      style: { ...node.style, width: COMPACT_NODE_WIDTH, "--graph-node-card-width": `${COMPACT_NODE_WIDTH}px` },
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
      const reverse = Boolean(from && to && from.x > to.x);
      const sameRank = Boolean(from && to && from.x === to.x);
      const lane = from && lanes.get(edge.id)?.map(point => ({ dx: point.x - from.x, dy: point.y - from.y, half: COMPACT_NODE_WIDTH / 2 }));
      const color = edgeFamilyColor(edgeFamily(String(edge.data?.relationship ?? "")));
      const marker = (value: Edge["markerEnd"]) => value && typeof value === "object" ? { ...value, color, width: 14, height: 14 } : value;
      return { ...edge, type: "compact", animated: false, ...(edge.markerEnd ? { markerEnd: marker(edge.markerEnd)! } : {}),
        ...(edge.markerStart ? { markerStart: marker(edge.markerStart)! } : {}), sourceHandle: reverse ? "context" : null, targetHandle: reverse || sameRank ? "context" : null,
        data: { ...edge.data, semanticLayout: true, individualLabel: true, lanePoints: lane && (reverse ? lane.reverse() : lane), quietLabel: edge.data?.isClusterEdge !== true,
          pathEmphasis: pathPairs.has(`${edge.source}\u0000${edge.target}`) || edge.data?.pathEmphasis === true } };
    }),
  };
}
