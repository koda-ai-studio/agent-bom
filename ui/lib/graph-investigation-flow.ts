import { MarkerType, type Edge, type Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

export type InvestigationFlow = "auto" | "exposure" | "identity" | "vulnerability" | "inventory";
const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);
const IDENTITIES = new Set(["user", "serviceAccount", "servicePrincipal", "federatedIdentity", "role", "managedIdentity"]);
const CONTEXT = new Set(["contains", "hosts", "hosted_on", "part_of", "belongs_to", "owns"]);
const FLOW = new Set(["exposed_to", "authenticates_as", "assumes", "inherits", "has_permission", "can_access", "accessed", "depends_on", "uses", "invoked", "calls", "stores"]);
const endpoint = (n: Node<LineageNodeData>) => n.data.nodeType === "apiGateway" || n.data.attributes?.resource_type === "application_endpoint";

function ingressAssessment(n: Node<LineageNodeData>): Record<string, unknown> | null {
  const attrs = n.data.attributes ?? {}, a = attrs.network_reachability_assessment;
  if (n.hidden || !a || typeof a !== "object" || Array.isArray(a)) return null;
  const assessment = a as Record<string, unknown>;
  return assessment.complete === true && assessment.decision === "allow" && assessment.source_scope === "internet"
    && typeof attrs.resource_id === "string" && Boolean(attrs.resource_id) && assessment.target_id === attrs.resource_id
    && Array.isArray(assessment.evidence_refs) && assessment.evidence_refs.length > 0
    && assessment.evidence_refs.every(ref => typeof ref === "string" && ref.trim()) ? assessment : null;
}

/** Display context from a target-bound assessment, never from names, IPs or a public flag.
 * This neither adds a persisted asset nor upgrades an attack-path receipt. */
function internetContext(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const extra: Node<LineageNodeData>[] = [], links: Edge[] = [];
  for (const n of nodes) {
    const assessment = ingressAssessment(n);
    if (!assessment) continue;
    // One boundary per target: never merge unrelated accounts or snapshots through a global Internet node.
    const id = `display:internet:${n.id}`;
    if (nodes.some(n => n.id === id)) continue;
    extra.push({ id, initialWidth: 240, initialHeight: 300, draggable: false, type: "cloudResourceNode", position: { x: 0, y: 0 }, data: { label: "Internet", nodeType: "cloudResource",
      displayOnly: true, displayTargetId: n.id, readingLabel: "Assessed ingress · snapshot", attributes: { resource_type: "internet_boundary" } } });
    links.push({ id: `${id}:ingress`, source: id, target: n.id, type: "smoothstep", markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: "#ea580c", strokeWidth: 1.7 },
      label: "Assessed ingress", data: { relationship: "exposed_to", displayOnly: true, traversable: false,
        evidence: assessment, evidenceMode: "inferred", individualLabel: true, quietLabel: true, directionEmphasis: true } });
  }
  return { nodes: [...nodes, ...extra], edges: [...edges, ...links] };
}

/** A finding belongs to a visual group only when all recorded finding links have one owner. */
export function withFindingOwners(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const ids = new Set(nodes.filter(n => !n.hidden).map(n => n.id));
  const owners = new Map<string, Set<string>>();
  for (const e of edges) {
    const finding = e.data?.relationship === "affects" ? e.source : e.data?.relationship === "vulnerable_to" ? e.target : null;
    const owner = finding === e.source ? e.target : e.source;
    if (finding) {
      if (!owners.has(finding)) owners.set(finding, new Set());
      owners.get(finding)!.add(owner);
    }
  }
  return nodes.map(n => {
    if (!FINDINGS.has(n.data.nodeType)) return n;
    const affected = owners.get(n.id);
    return { ...n, data: { ...n.data, readingFinding: true, readingOwner: affected?.size === 1 && ids.has([...affected][0]!) ? [...affected][0] : undefined } };
  });
}

function inferredScenario(nodes: Node<LineageNodeData>[], edges: Edge[]): InvestigationFlow {
  if (nodes.some(n => ingressAssessment(n)) || nodes.some(endpoint) && edges.some(e => e.data?.relationship === "exposed_to")) return "exposure";
  if (edges.some(e => ["has_permission", "can_access", "assumes"].includes(String(e.data?.relationship)))) return "identity";
  if (nodes.some(n => FINDINGS.has(n.data.nodeType))) return "vulnerability";
  return "inventory";
}

/** Layout changes reading order, never relationship direction, reachability or finding identity. */
export function investigationFlow(input: Node<LineageNodeData>[], inputEdges: Edge[], requested: InvestigationFlow, narrowViewport = false) {
  const shortCaptions = input.every(n => String(n.data.label).length <= 28);
  const columnGap = shortCaptions ? 420 : 520;
  const rowGap = narrowViewport ? 440 : shortCaptions ? 300 : 340;
  const contextGap = narrowViewport ? 880 : shortCaptions ? 480 : 680;
  const scenario = requested === "auto" ? inferredScenario(input, inputEdges) : requested;
  if (requested === "auto" && !input.some(n => ingressAssessment(n) || endpoint(n) || ["account", "cluster"].includes(n.data.nodeType))) {
    return { nodes: input, edges: inputEdges, scenario };
  }
  const owned = withFindingOwners(input, inputEdges);
  const { nodes, edges } = scenario === "exposure" ? internetContext(owned, inputEdges) : { nodes: owned, edges: inputEdges };
  if (scenario === "inventory" && requested === "auto" || nodes.length > 80 || nodes.some(n => n.data.rollup || n.type === "clusterPillNode")
    || requested === "auto" && !nodes.some(n => n.data.displayOnly || endpoint(n) || ["account", "cluster"].includes(n.data.nodeType))) {
    return { nodes, edges, scenario };
  }
  const visible = nodes.filter(n => !n.hidden), byId = new Map(visible.map(n => [n.id, n]));
  const principal = (n: Node<LineageNodeData>) => IDENTITIES.has(n.data.nodeType);
  const incomingEndpoint = (n: Node<LineageNodeData>) => edges.some(e => {
    const source = byId.get(e.source);
    return e.target === n.id && e.data?.relationship === "exposed_to" && source && (endpoint(source) || source.data.displayOnly);
  });
  const roots = visible.filter(n => scenario === "inventory" ? n.data.nodeType === "account" || edges.some(e => e.source === n.id && CONTEXT.has(String(e.data?.relationship))) && !edges.some(e => CONTEXT.has(String(e.data?.relationship)) && (["hosted_on", "part_of", "belongs_to"].includes(String(e.data?.relationship)) ? e.source : e.target) === n.id) && !FINDINGS.has(n.data.nodeType)
    : scenario === "exposure" ? n.data.displayOnly || endpoint(n) && !incomingEndpoint(n)
    : scenario === "identity" ? principal(n) && !edges.some(e => e.target === n.id && principal(byId.get(e.source) ?? n))
      : n.data.nodeType === "container" && !["image"].includes(String(n.data.attributes?.container_kind))
        && !edges.some(e => e.source === n.id && CONTEXT.has(String(e.data?.relationship)) && byId.get(e.target)?.data.nodeType === "container"));
  if (!roots.length) roots.push(...visible.filter(n => scenario === "vulnerability" && n.data.nodeType === "package"));
  const rank = new Map<string, number>();
  const queue = roots.sort((a, b) => Number(Boolean(b.data.displayOnly)) - Number(Boolean(a.data.displayOnly)) || a.id.localeCompare(b.id));
  for (const n of queue) rank.set(n.id, 0);
  // Bounded BFS follows only recorded flow links. Ownership is attached separately below.
  for (let index = 0; index < queue.length; index++) {
    const n = queue[index]!;
    for (const e of edges) {
      const relationship = String(e.data?.relationship);
      const reverse = scenario === "inventory" && ["hosted_on", "part_of", "belongs_to"].includes(relationship);
      const source = reverse ? e.target : e.source, target = reverse ? e.source : e.target;
      if (source !== n.id || !(scenario === "inventory" ? CONTEXT : FLOW).has(relationship) || !byId.has(target) || rank.has(target)) continue;
      if (scenario === "vulnerability" && ["assumes", "authenticates_as", "has_permission"].includes(relationship)) continue;
      rank.set(target, rank.get(n.id)! + 1); queue.push(byId.get(target)!);
    }
  }
  const positions = new Map<string, { x: number; y: number }>(), slots = new Map<number, number>();
  for (const n of queue) {
    const column = rank.get(n.id)!;
    const row = slots.get(column) ?? 0; slots.set(column, row + 1);
    positions.set(n.id, { x: column * columnGap, y: row * rowGap });
  }
  for (let pass = 0; pass < 8; pass++) for (const e of edges) {
    if (!CONTEXT.has(String(e.data?.relationship)) && !(scenario === "identity" && ["assumes", "authenticates_as", "exposed_to"].includes(String(e.data?.relationship)))) continue;
    const reverse = ["hosted_on", "part_of", "belongs_to"].includes(String(e.data?.relationship));
    const parent = reverse ? e.target : e.source, child = reverse ? e.source : e.target;
    if (byId.has(parent) && positions.has(child) && !positions.has(parent)) {
      const at = positions.get(child)!;
      positions.set(parent, { x: at.x + columnGap, y: at.y < 0 ? at.y : -contextGap });
    }
  }
  // Sibling workloads stay with deployment context, outside the selected entry flow.
  for (let pass = 0; pass < 8; pass++) for (const e of edges) {
    if (!CONTEXT.has(String(e.data?.relationship))) continue;
    const reverse = ["hosted_on", "part_of", "belongs_to"].includes(String(e.data?.relationship));
    const parent = reverse ? e.target : e.source, child = reverse ? e.source : e.target;
    if (byId.has(child) && positions.has(parent) && !positions.has(child)) {
      const at = positions.get(parent)!;
      positions.set(child, { x: at.x + columnGap, y: Math.min(at.y, -contextGap) });
    }
  }
  // Findings are branches from the affected component, not steps through a CVE to data.
  for (const n of visible) if (n.data.readingOwner && positions.has(n.data.readingOwner)) {
    const owner = positions.get(n.data.readingOwner)!;
    positions.set(n.id, { x: owner.x + columnGap, y: scenario === "vulnerability" ? owner.y : owner.y - rowGap });
  }
  const extraRow = Math.max(0, ...[...positions.values()].map(p => p.y)) + contextGap;
  let extra = 0;
  for (const n of visible) if (!positions.has(n.id)) { positions.set(n.id, { x: (extra % 4) * columnGap, y: extraRow + Math.floor(extra / 4) * rowGap }); extra++; }
  // Reserve caption space even for multiple findings and converging ownership branches.
  const occupied: { x: number; y: number }[] = [];
  for (const n of [...visible].sort((a, b) => a.id.localeCompare(b.id))) {
    const at = { ...positions.get(n.id)! };
    while (occupied.some(p => p.x === at.x && Math.abs(p.y - at.y) < rowGap)) at.y -= rowGap;
    occupied.push(at); positions.set(n.id, at);
  }
  return { scenario, nodes: nodes.map(n => ({ ...n, position: positions.get(n.id) ?? n.position,
    style: { ...n.style, minHeight: 300 }, data: { ...n.data, evidenceFlow: true } })), edges: edges.map(e => ({ ...e,
    ...(CONTEXT.has(String(e.data?.relationship)) && (positions.get(e.source)?.x ?? 0) > (positions.get(e.target)?.x ?? 0)
      ? { sourceHandle: "context", targetHandle: "context" } : {}),
    data: { ...e.data, quietLabel: true, individualLabel: true, directionEmphasis: true } })) };
}
