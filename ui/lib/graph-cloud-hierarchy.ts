import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { assetKindLabel } from "@/lib/asset-icon-registry";

const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);
const LANES: Record<string, number> = { account: 0, cluster: 1, apiGateway: 1, container: 2,
  role: 3, serviceAccount: 3, managedIdentity: 3, servicePrincipal: 3, dataStore: 4 };
const CAPTIONS: Record<string, string> = { account: "Account · ownership scope", cluster: "Cluster · hosting",
  apiGateway: "API gateway · entry point", container: "Application workload", role: "Identity · permissions role",
  serviceAccount: "Identity · service account", managedIdentity: "Managed identity", servicePrincipal: "Identity · service principal",
  dataStore: "Data resource" };

/** A bounded cloud view groups recorded entity roles, not inferred execution.
 * Ambiguous/shared findings and other graph kinds retain the general layout.
 * No node, relationship, direction or evidence record is added or removed. */
export function cloudHierarchyLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  if (nodes.length > 16 || edges.length > 20 || !nodes.some(n => n.data.nodeType === "account")
    || !nodes.some(n => n.data.nodeType === "role") || !nodes.some(n => n.data.nodeType === "container")) return null;
  if (nodes.some(n => n.data.rollup || n.type === "clusterPillNode"
    || (!FINDINGS.has(n.data.nodeType) && !Object.hasOwn(LANES, n.data.nodeType))
    || (n.data.nodeType === "container" && n.data.attributes?.container_kind !== "workload"))) return null;
  const byId = new Map(nodes.map(n => [n.id, n]));
  const owners = new Map<string, string>();
  const attachments = new Set<string>();
  for (const finding of nodes.filter(n => FINDINGS.has(n.data.nodeType))) {
    const links = edges.filter(e => e.source === finding.id || e.target === finding.id);
    // Multiple affected assets need their original topology, not an arbitrary parent.
    if (links.length !== 1) return null;
    const link = links[0]!;
    const owner = link.data?.relationship === "affects" && link.source === finding.id ? link.target
      : link.data?.relationship === "vulnerable_to" && link.target === finding.id ? link.source : null;
    if (!owner || !byId.has(owner) || FINDINGS.has(byId.get(owner)!.data.nodeType)
      || [...owners.values()].includes(owner)) return null;
    owners.set(finding.id, owner); attachments.add(link.id);
  }
  const lanes = new Map<number, Node<LineageNodeData>[]>();
  for (const n of nodes.filter(n => !FINDINGS.has(n.data.nodeType))) {
    const lane = LANES[n.data.nodeType]!;
    lanes.set(lane, [...(lanes.get(lane) ?? []), n]);
  }
  if ([...lanes.values()].some(lane => lane.length > 3)) return null;
  const rowCount = Math.max(...[...lanes.values()].map(lane => lane.length));
  const positions = new Map<string, { x: number; y: number }>();
  for (const [lane, members] of [...lanes.entries()].sort(([a], [b]) => a - b)) {
    const parentRows = (n: Node) => edges.filter(e => e.target === n.id && !attachments.has(e.id))
      .flatMap(e => positions.has(e.source) ? [positions.get(e.source)!.y] : []);
    const preferredRow = (n: Node) => {
      const rows = parentRows(n);
      return rows.length ? rows.reduce((a, b) => a + b, 0) / rows.length : 0;
    };
    members.sort((a, b) => preferredRow(a) - preferredRow(b) || a.id.localeCompare(b.id)).forEach((n, row) => {
      const y = members.length === 1 && parentRows(n).length ? preferredRow(n) : ((rowCount - members.length) / 2 + row) * 720;
      positions.set(n.id, { x: lane * 640 + (lane === 4 ? 400 : 0), y });
    });
  }
  for (const [finding, owner] of owners) {
    const at = positions.get(owner)!;
    positions.set(finding, { x: at.x, y: at.y + 360 });
  }
  return {
    nodes: nodes.map(n => ({ ...n, position: positions.get(n.id)!, style: { ...n.style, minHeight: 324 },
      data: { ...n.data, readingLabel: n.data.nodeType === "dataStore"
        ? assetKindLabel({ nodeType: n.data.nodeType, entityType: n.data.entityType, attributes: n.data.attributes }) === "Data"
          ? "Data resource" : `Data · ${assetKindLabel({ nodeType: n.data.nodeType, entityType: n.data.entityType, attributes: n.data.attributes })}`
        : CAPTIONS[n.data.nodeType] } })),
    edges: edges.map((e): Edge => ({ ...e,
      ...(attachments.has(e.id) ? { targetHandle: "context" } : {}),
      data: { ...e.data, findingAttachment: attachments.has(e.id), quietLabel: attachments.has(e.id), boundedOverview: true, roomyOverview: true, directionEmphasis: true },
    })),
  };
}
