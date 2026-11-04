import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { accessEvidenceQualifier } from "@/lib/graph-access-evidence";
import { assetKindLabel, assetServiceLabel } from "@/lib/asset-icon-registry";

const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);
const LANES: Record<string, number> = { account: 0, cluster: 1, apiGateway: 1, container: 2,
  role: 3, serviceAccount: 3, managedIdentity: 3, servicePrincipal: 3, dataStore: 4 };
const GROUPS = ["Account scope", "Infrastructure", "Applications", "Identities", "Data"] as const;
const CAPTIONS: Record<string, string> = { account: "Account", cluster: "Cluster",
  apiGateway: "API gateway", container: "Application", role: "Permission role",
  serviceAccount: "Service account", managedIdentity: "Managed identity", servicePrincipal: "Service principal",
  dataStore: "Data resource", vulnerability: "Vulnerability", misconfiguration: "Configuration finding", driftIncident: "Drift finding" };
const VERBS: Record<string, string> = { contains: "Contains", hosts: "Hosts application", authenticates_as: "Uses role",
  has_permission: "Permission on", exposed_to: "Exposure link", vulnerable_to: "Has vulnerability", affects: "Finding on" };

function cloudCaption(data: LineageNodeData): string | undefined {
  const input = { nodeType: data.nodeType, entityType: data.entityType, attributes: data.attributes, provider: data.dimensions?.cloud_provider };
  const service = assetServiceLabel(input);
  if (service) return service;
  if (data.nodeType !== "dataStore") return CAPTIONS[data.nodeType];
  const label = assetKindLabel(input);
  return label === "Data" ? "Data resource" : label;
}

/** A bounded cloud view groups recorded entity roles, not inferred execution.
 * Ambiguous/shared findings and other graph kinds retain the general layout.
 * No node, relationship, direction or evidence record is added or removed. */
export function cloudHierarchyLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  if (nodes.length > 16 || edges.length > 20 || !nodes.some(n => n.data.nodeType === "account")
    || !nodes.some(n => n.data.nodeType && LANES[n.data.nodeType] === 3) || !nodes.some(n => n.data.nodeType === "container")) return null;
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
    if (!owner || !byId.has(owner) || FINDINGS.has(byId.get(owner)!.data.nodeType)) return null;
    owners.set(finding.id, owner); attachments.add(link.id);
  }
  // Build placement from recorded containment/hosting/identity relationships.
  // Cross-links (including exposure) keep their direction but do not invent a parent.
  const visible = nodes.filter(n => !n.hidden);
  const parents = new Map<string, string>();
  for (const e of [...edges].sort((a, b) => a.id.localeCompare(b.id))) {
    if (!e.hidden && ["contains", "hosts", "authenticates_as", "has_permission"].includes(String(e.data?.relationship))
      && byId.has(e.source) && byId.has(e.target) && !byId.get(e.source)!.hidden && !byId.get(e.target)!.hidden) {
      if (parents.has(e.target) && parents.get(e.target) !== e.source) return null;
      parents.set(e.target, e.source);
    }
  }
  for (const [finding, owner] of owners) if (!byId.get(finding)!.hidden) parents.set(finding, owner);
  const positions = new Map<string, { x: number; y: number }>();
  const visiting = new Set<string>();
  type Branch = { id: string; depth: number; y: number }[];
  // Keep the deepest recorded asset branch on a shared baseline. Side branches
  // occupy the nearest free row; entity categories never determine coordinates.
  const branch = (id: string): Branch | null => {
    if (visiting.has(id)) return null;
    visiting.add(id);
    const children = visible.filter(n => parents.get(n.id) === id).sort((a, b) => a.id.localeCompare(b.id));
    const branches: Branch[] = [];
    for (const child of children) {
      const tree = branch(child.id);
      if (!tree) return null;
      branches.push(tree);
    }
    const assetDepth = (tree: Branch) => Math.max(...tree.filter(n => !FINDINGS.has(byId.get(n.id)!.data.nodeType)).map(n => n.depth), -1);
    branches.sort((a, b) => assetDepth(b) - assetDepth(a) || a[0]!.id.localeCompare(b[0]!.id));
    const placed: Branch = [{ id, depth: 0, y: 0 }];
    branches.forEach((tree, index) => {
      let offset = 0;
      const sign = byId.get(id)!.data.nodeType === "account" ? 1 : -1;
      const collides = () => tree.some(n => placed.some(other => other.depth === n.depth + 1 && Math.abs(other.y - n.y - offset) < 340));
      if (index) offset = sign * 340;
      while (collides()) offset += sign * 340;
      placed.push(...tree.map(n => ({ ...n, depth: n.depth + 1, y: n.y + offset })));
    });
    visiting.delete(id);
    return placed;
  };
  let bottom = 0;
  for (const root of visible.filter(n => !parents.has(n.id)).sort((a, b) => a.id.localeCompare(b.id))) {
    const tree = branch(root.id);
    if (!tree) return null;
    const top = Math.min(...tree.map(n => n.y));
    for (const n of tree) positions.set(n.id, { x: n.depth * 600, y: n.y - top + bottom });
    bottom += Math.max(...tree.map(n => n.y)) - top + 340;
  }
  if (positions.size !== visible.length) return null;
  const connectionSummaries = new Map(nodes.map(n => [n.id, ["contains", "hosts"].flatMap(relationship => {
    const targets = [...new Set(edges.filter(e => e.source === n.id && e.data?.relationship === relationship && byId.has(e.target) && !byId.get(e.target)?.hidden && !e.hidden)
      .map(e => e.target))].sort();
    return targets.length > 1 ? [{ relationship, label: `${targets.length} ${relationship === "hosts" && targets.every(id => byId.get(id)?.data.nodeType === "container") ? "applications" : "resources"}`, targets }] : [];
  })]));
  return {
    nodes: nodes.map(n => ({ ...n, position: positions.get(n.id) ?? n.position, style: { ...n.style, minHeight: 300, paddingTop: 0 },
      data: { ...n.data, readingGroup: GROUPS[LANES[n.data.nodeType] ?? LANES[byId.get(owners.get(n.id) ?? "")?.data.nodeType ?? ""]!],
        readingConnections: connectionSummaries.get(n.id), readingOwner: owners.get(n.id), readingFinding: FINDINGS.has(n.data.nodeType), readingLabel: cloudCaption(n.data) } })),
    edges: edges.map((e): Edge => {
      const relationship = String(e.data?.relationship ?? "");
      const qualifier = accessEvidenceQualifier(relationship, e.data);
      const verb = relationship === "authenticates_as" && byId.get(e.target)?.data.nodeType !== "role" ? "Uses identity" : VERBS[relationship];
      return { ...e, ...(verb ? { label: `${verb}${qualifier ? ` · ${qualifier}` : ""}` } : {}),
        ...(attachments.has(e.id) && owners.get(e.source) ? { sourceHandle: "context", targetHandle: "context" } : {}),
        data: { ...e.data, individualLabel: true, stackedQualifier: true, quietLabel: true, boundedOverview: true, roomyOverview: true, directionEmphasis: true },
      };
    }),
  };
}
