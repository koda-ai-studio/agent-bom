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
  return image ? "Image inventory" : "Deployment occurrence";
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
    for (const node of group) node.data.occurrenceRole = containerOccurrenceRole(node.data.dataSources ?? []);
  }
}
