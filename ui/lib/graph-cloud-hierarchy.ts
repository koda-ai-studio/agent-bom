import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { accessEvidenceQualifier } from "@/lib/graph-access-evidence";
import { assetKindLabel } from "@/lib/asset-icon-registry";

const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);
const LANES: Record<string, number> = { account: 0, cluster: 1, apiGateway: 1, container: 2,
  role: 3, serviceAccount: 3, managedIdentity: 3, servicePrincipal: 3, dataStore: 4 };
const LANE_X = [0, 600, 1200, 1940, 2680] as const;
const GROUPS = ["Account scope", "Infrastructure", "Applications", "Identities", "Data"] as const;
const CAPTIONS: Record<string, string> = { account: "Account", cluster: "Cluster",
  apiGateway: "API gateway", container: "Application", role: "Permission role",
  serviceAccount: "Service account", managedIdentity: "Managed identity", servicePrincipal: "Service principal",
  dataStore: "Data resource", vulnerability: "Vulnerability", misconfiguration: "Configuration finding", driftIncident: "Drift finding" };
const VERBS: Record<string, string> = { contains: "Contains", hosts: "Hosts application", authenticates_as: "Uses role",
  has_permission: "Permission on", exposed_to: "Exposure link", vulnerable_to: "Has vulnerability", affects: "Finding on" };

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
      const y = members.length === 1 && parentRows(n).length ? preferredRow(n) : ((rowCount - members.length) / 2 + row) * 760;
      positions.set(n.id, { x: LANE_X[lane]!, y });
    });
  }
  for (const [finding, owner] of owners) {
    const at = positions.get(owner)!;
    positions.set(finding, { x: at.x, y: at.y + 430 });
  }
  const connectionSummaries = new Map(nodes.map(n => [n.id, ["contains", "hosts"].flatMap(relationship => {
    const targets = [...new Set(edges.filter(e => e.source === n.id && e.data?.relationship === relationship && byId.has(e.target) && !byId.get(e.target)?.hidden && !e.hidden)
      .map(e => e.target))].sort();
    return targets.length > 1 ? [{ relationship, label: `${relationship === "hosts" ? "Hosts" : "Contains"} ×${targets.length}`, targets }] : [];
  })]));
  return {
    nodes: nodes.map(n => ({ ...n, position: positions.get(n.id)!, style: { ...n.style, minHeight: FINDINGS.has(n.data.nodeType) ? 200 : 424, paddingTop: FINDINGS.has(n.data.nodeType) ? 0 : 100 },
      data: { ...n.data, readingGroup: GROUPS[LANES[n.data.nodeType] ?? LANES[byId.get(owners.get(n.id) ?? "")?.data.nodeType ?? ""]!],
        readingConnections: connectionSummaries.get(n.id), readingOwner: owners.get(n.id), readingFinding: FINDINGS.has(n.data.nodeType), readingLabel: n.data.nodeType === "dataStore"
        ? assetKindLabel({ nodeType: n.data.nodeType, entityType: n.data.entityType, attributes: n.data.attributes }) === "Data"
          ? "Data resource" : assetKindLabel({ nodeType: n.data.nodeType, entityType: n.data.entityType, attributes: n.data.attributes })
        : CAPTIONS[n.data.nodeType] } })),
    edges: edges.map((e): Edge => {
      const relationship = String(e.data?.relationship ?? "");
      const qualifier = accessEvidenceQualifier(relationship, e.data);
      const verb = relationship === "authenticates_as" && byId.get(e.target)?.data.nodeType !== "role" ? "Uses identity" : VERBS[relationship];
      return { ...e, ...(verb ? { label: `${verb}${qualifier ? ` · ${qualifier}` : ""}` } : {}),
        ...(attachments.has(e.id) ? { targetHandle: "context" } : {}),
        data: { ...e.data, findingAttachment: attachments.has(e.id), individualLabel: true, stackedQualifier: true, quietLabel: attachments.has(e.id) || (connectionSummaries.get(e.source)?.some(s => s.relationship === relationship) ?? false), boundedOverview: true, roomyOverview: true, directionEmphasis: true },
      };
    }),
  };
}
