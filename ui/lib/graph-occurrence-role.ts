import type { Node } from "@xyflow/react";

import type { LineageNodeData } from "@/components/lineage-nodes";

const IMAGE_SOURCE = /sbom|cyclonedx|spdx|syft|image[_-]?scan|registry/i;
const DEPLOYMENT_SOURCE = /kubernetes|k8s|helm|iac|terraform|ecs|deployment|workload/i;
const DIGEST_SUFFIX = /@sha256:[0-9a-f]{12,}$/i;

/** One image can be recorded both as inventory (SBOM) and as a deployed workload. */
export function containerOccurrenceRole(dataSources: readonly string[]): string | undefined {
  const image = dataSources.some((source) => IMAGE_SOURCE.test(source));
  const deployment = dataSources.some((source) => DEPLOYMENT_SOURCE.test(source));
  if (image === deployment) return undefined;
  return image ? "Image inventory" : "Deployment";
}

/** The full digest belongs in the details panel; the canvas keeps the readable name. */
export function canvasNodeLabel(label: string): string {
  return label.replace(DIGEST_SUFFIX, "") || label;
}

/** Name the role only where two visible containers would otherwise read as one. */
export function assignOccurrenceRoles(nodes: Node<LineageNodeData>[]): void {
  const byName = new Map<string, Node<LineageNodeData>[]>();
  for (const node of nodes) {
    if (node.data.nodeType !== "container") continue;
    const name = canvasNodeLabel(node.data.label);
    byName.set(name, [...(byName.get(name) ?? []), node]);
  }
  for (const group of byName.values()) {
    if (group.length < 2) continue;
    // A recorded image/workload kind is already the node's badge; the role chip would repeat it.
    for (const node of group) node.data.occurrenceRole = node.data.attributes?.container_kind ? undefined : containerOccurrenceRole(node.data.dataSources ?? []);
  }
}

/** Use only already-public descriptive metadata, never decode identity hashes or paths. */
function readableContext(node: Node<LineageNodeData>): string | undefined {
  const attrs = node.data.attributes ?? {};
  const options: [string, unknown][] = [
    ["Workspace", attrs.workspace_name], ["Project", attrs.project_name],
    ["Repository", attrs.repository_name], ["Enrollment", attrs.enrollment_name],
    ["Environment", attrs.environment ?? node.data.rollup?.context?.environment],
    ["Workload", node.data.rollup?.context?.workload],
  ];
  for (const [kind, raw] of options) {
    if (typeof raw !== "string") continue;
    const value = raw.trim();
    if (!value || value.length > 80 || /[<>\\/\n\r]/.test(value) || /^[a-f0-9-]{12,}$/i.test(value)) continue;
    return `${kind}: ${value}`;
  }
  return undefined;
}

/** Distinguish collisions without displaying private config paths or launch arguments. */
export function assignCollisionScopes(nodes: Node<LineageNodeData>[]): void {
  const groups = new Map<string, Node<LineageNodeData>[]>();
  for (const node of nodes) {
    node.data.identityContext = undefined;
    const key = JSON.stringify([node.data.entityType ?? node.data.nodeType, canvasNodeLabel(node.data.label)]);
    const group = groups.get(key);
    if (group) group.push(node);
    else groups.set(key, [node]);
  }
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    const candidates = group.map(readableContext);
    const counts = new Map<string, number>();
    for (const value of candidates) if (value) counts.set(value, (counts.get(value) ?? 0) + 1);
    // Ordinals distinguish the visible occurrences. They are display labels,
    // not persistent identities; full canonical IDs remain in the inspector.
    const ordinals = new Map([...group].sort((a, b) => a.id.localeCompare(b.id)).map((node, index) => [node.id, index + 1]));
    group.forEach((node, index) => {
      const context = candidates[index] ?? `Instance ${ordinals.get(node.id)}`;
      node.data.identityContext = (counts.get(context) ?? 0) > 1 ? `${context} · instance ${ordinals.get(node.id)}` : context;
    });
  }
}
