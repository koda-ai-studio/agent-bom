import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

export type InvestigationFlow = "auto" | "exposure" | "identity" | "vulnerability" | "inventory";
export type SpecificFlow = Exclude<InvestigationFlow, "auto">;
export type FlowNode = Node<LineageNodeData>;

const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);
const IDENTITIES = new Set(["user", "serviceAccount", "servicePrincipal", "federatedIdentity", "role", "managedIdentity"]);
/** The recorded child points at its parent for these; `contains` and friends point the other way. */
const CHILD_TO_PARENT = new Set(["hosted_on", "part_of", "belongs_to"]);
const PARENT_TO_CHILD = new Set(["contains", "hosts", "owns"]);
const STEPS = new Set(["exposed_to", "authenticates_as", "assumes", "inherits", "has_permission", "can_access", "accessed", "depends_on", "uses", "invoked", "calls", "stores"]);
const IDENTITY_HOPS = new Set(["assumes", "authenticates_as", "has_permission"]);
const FINDING_LINKS = new Set(["vulnerable_to", "affects", "exhibits_drift"]);
/** Kubernetes Service types with no recorded path from outside the cluster. */
const INTERNAL_SERVICE_TYPES = new Set(["ClusterIP", "ExternalName"]);

export const relationshipOf = (edge: Edge) => String(edge.data?.relationship);
export const isFinding = (node: FlowNode) => FINDINGS.has(node.data.nodeType);
export const isPrincipal = (node: FlowNode) => IDENTITIES.has(node.data.nodeType);
export const isEndpoint = (node: FlowNode) => node.data.nodeType === "apiGateway" || node.data.attributes?.resource_type === "application_endpoint";

export function isInternalService(node: FlowNode): boolean {
  if (node.data.attributes?.kubernetes_kind !== "Service") return false;
  const type = node.data.attributes.service_type;
  return typeof type !== "string" || INTERNAL_SERVICE_TYPES.has(type);
}

/** Parent and child of a containment link, or null when the edge is not one. */
export function ownership(edge: Edge): { parent: string; child: string } | null {
  const relationship = relationshipOf(edge);
  if (PARENT_TO_CHILD.has(relationship)) return { parent: edge.source, child: edge.target };
  return CHILD_TO_PARENT.has(relationship) ? { parent: edge.target, child: edge.source } : null;
}

export function ingressAssessment(node: FlowNode): Record<string, unknown> | null {
  const attributes = node.data.attributes ?? {}, value = attributes.network_reachability_assessment;
  if (node.hidden || !value || typeof value !== "object" || Array.isArray(value)) return null;
  const assessment = value as Record<string, unknown>;
  return assessment.complete === true && assessment.decision === "allow" && assessment.source_scope === "internet"
    && typeof attributes.resource_id === "string" && Boolean(attributes.resource_id) && assessment.target_id === attributes.resource_id
    && Array.isArray(assessment.evidence_refs) && assessment.evidence_refs.length > 0
    && assessment.evidence_refs.every(ref => typeof ref === "string" && ref.trim()) ? assessment : null;
}

export const isExposureEntry = (node: FlowNode) => Boolean(node.data.displayOnly) || Boolean(ingressAssessment(node)) || (isEndpoint(node) && !isInternalService(node));

/** A controller owning a pod or another controller, as distinct from a pod's containers or a namespace's members. */
function isControllerLink(edge: Edge, source: FlowNode, target: FlowNode): boolean {
  return relationshipOf(edge) === "contains" && source.data.attributes?.container_kind === "workload"
    && ["workload", "pod"].includes(String(target.data.attributes?.container_kind));
}

/** A recorded identity hop the collector marked as not usable, such as an unmounted token. */
export const isBlockedIdentityHop = (edge: Edge) => edge.data?.traversable === false && ["assumes", "authenticates_as"].includes(relationshipOf(edge));

/**
 * The directed reading order a flow may follow along one recorded edge, or null.
 * Kubernetes routes are recorded non-traversable until network evidence exists; they still
 * order an exposure view and read as dashed context. Other non-traversable hops never advance.
 * Walking from a pod up to its controller is the one step read against the edge's direction:
 * identity and secret access are recorded on the controller, and the edge itself is unchanged.
 */
export function flowStep(flow: SpecificFlow, edge: Edge, source: FlowNode, target: FlowNode): [string, string] | null {
  const forward: [string, string] = [edge.source, edge.target];
  const relationship = relationshipOf(edge);
  if (flow === "inventory") {
    const link = ownership(edge);
    return link ? [link.parent, link.child] : null;
  }
  if (flow === "exposure") {
    if (isControllerLink(edge, source, target)) return [edge.target, edge.source];
    if (relationship === "hosts" || relationship === "exposed_to") return forward;
  }
  if (flow === "vulnerability") {
    if (relationship === "contains" && target.data.nodeType === "package") return forward;
    if (FINDING_LINKS.has(relationship)) return isFinding(source) ? [edge.target, edge.source] : forward;
    if (IDENTITY_HOPS.has(relationship)) return null;
  }
  return STEPS.has(relationship) && edge.data?.traversable !== false ? forward : null;
}

export function flowRoots(flow: SpecificFlow, visible: FlowNode[], edges: Edge[]): FlowNode[] {
  const byId = new Map(visible.map(node => [node.id, node]));
  const incoming = (node: FlowNode, from: (source: FlowNode, edge: Edge) => boolean) => edges.some(edge => {
    const source = byId.get(edge.source);
    return edge.target === node.id && source !== undefined && from(source, edge);
  });
  if (flow === "exposure") return visible.filter(node => node.data.displayOnly
    || isExposureEntry(node) && !incoming(node, (source, edge) => relationshipOf(edge) === "exposed_to" && (isEndpoint(source) || Boolean(source.data.displayOnly))));
  if (flow === "identity") {
    const principals = visible.filter(isPrincipal);
    const roots = principals.filter(node => !incoming(node, source => isPrincipal(source)));
    // A cycle of principals has no natural start; open it at a stable member rather than drop it.
    return roots.length ? roots : principals.slice().sort((a, b) => a.id.localeCompare(b.id)).slice(0, 1);
  }
  if (flow === "inventory") {
    const children = new Set(edges.flatMap(edge => { const link = ownership(edge); return link && byId.has(link.parent) ? [link.child] : []; }));
    const parents = new Set(edges.flatMap(edge => { const link = ownership(edge); return link && byId.has(link.child) ? [link.parent] : []; }));
    return visible.filter(node => !isFinding(node) && (node.data.nodeType === "account" || parents.has(node.id) && !children.has(node.id)));
  }
  const containsContainer = new Set(edges.flatMap(edge => {
    const link = ownership(edge);
    return link && byId.get(link.child)?.data.nodeType === "container" ? [link.parent] : [];
  }));
  const workloads = visible.filter(node => node.data.nodeType === "container" && node.data.attributes?.container_kind !== "image" && !containsContainer.has(node.id));
  return workloads.length ? workloads : visible.filter(node => node.data.nodeType === "package");
}

/** A finding belongs to a visual group only when all recorded finding links have one owner. */
export function withFindingOwners(nodes: FlowNode[], edges: Edge[]): FlowNode[] {
  const visibleIds = new Set(nodes.filter(node => !node.hidden).map(node => node.id));
  const findingIds = new Set(nodes.filter(isFinding).map(node => node.id));
  const owners = new Map<string, Set<string>>();
  for (const edge of edges) {
    if (!FINDING_LINKS.has(relationshipOf(edge))) continue;
    const finding = findingIds.has(edge.target) ? edge.target : findingIds.has(edge.source) ? edge.source : null;
    if (!finding) continue;
    if (!owners.has(finding)) owners.set(finding, new Set());
    owners.get(finding)!.add(finding === edge.source ? edge.target : edge.source);
  }
  return nodes.map(node => {
    if (!isFinding(node)) return node;
    const affected = [...(owners.get(node.id) ?? [])];
    return { ...node, data: { ...node.data, readingFinding: true, readingOwner: affected.length === 1 && visibleIds.has(affected[0]!) ? affected[0] : undefined } };
  });
}
