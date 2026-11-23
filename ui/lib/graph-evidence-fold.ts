import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

/** A manifest or image inventory that records a package, shown on the package's card instead of as its own card. */
export type SeenIn = { id: string; label: string; role: "image inventory" | "manifest"; runBy?: string | undefined };

const MANIFESTS = new Set(["sourceFile", "configFile"]);
const RECORDS_PACKAGE = new Set(["contains", "depends_on"]);

/**
 * The overview of a correlation reads the workload and access story; which manifest pins a package and which image
 * inventory lists it is dependency evidence, drawn in full in that view. Here each manifest or image inventory whose
 * only links record one package (and, for an image, the one workload that runs it) folds into that package's card as
 * a "seen in" source, so its long link into the package does not cross the workload's links. Nothing is folded that
 * would leave the package or the workload with no drawn link.
 */
export function foldPackageEvidence(nodes: Node<LineageNodeData>[], edges: Edge[]): { nodes: Node<LineageNodeData>[]; edges: Edge[]; folded: number } {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const linksOf = (id: string) => edges.filter(edge => edge.source !== edge.target && (edge.source === id || edge.target === id));
  const kind = (edge: Edge) => String(edge.data?.relationship ?? "");
  const seen = new Map<string, SeenIn[]>(), hidden = new Set<string>();
  for (const node of nodes) {
    const image = node.data.nodeType === "container" && edges.some(edge => edge.target === node.id && kind(edge) === "runs");
    if (!image && !MANIFESTS.has(node.data.nodeType)) continue;
    const links = linksOf(node.id);
    const recorded = links.filter(edge => edge.source === node.id && RECORDS_PACKAGE.has(kind(edge)) && byId.get(edge.target)?.data.nodeType === "package");
    const runs = links.filter(edge => edge.target === node.id && kind(edge) === "runs");
    const packages = new Set(recorded.map(edge => edge.target));
    if (packages.size !== 1 || recorded.length + (image ? runs.length : 0) !== links.length || (image && runs.length !== 1)) continue;
    const pkg = [...packages][0]!, workload = runs[0]?.source;
    // The package and the workload keep at least one other drawn link.
    if (linksOf(pkg).every(edge => edge.source === node.id || hidden.has(edge.source))) continue;
    if (workload && linksOf(workload).every(edge => edge.target === node.id)) continue;
    hidden.add(node.id);
    seen.set(pkg, [...(seen.get(pkg) ?? []), { id: node.id, label: node.data.label, role: image ? "image inventory" : "manifest",
      ...(workload ? { runBy: byId.get(workload)?.data.label ?? workload } : {}) }]);
  }
  if (!hidden.size) return { nodes, edges, folded: 0 };
  return {
    nodes: nodes.filter(node => !hidden.has(node.id)).map(node => seen.has(node.id) ? { ...node, data: { ...node.data, seenIn: seen.get(node.id) } } : node),
    edges: edges.filter(edge => !hidden.has(edge.source) && !hidden.has(edge.target)),
    folded: hidden.size,
  };
}

/** "Seen in 2 sources: <image> image inventory, run by <workload>; <file> manifest", for tooltips and assistive text. */
export function seenInSummary(seenIn: readonly SeenIn[]): string {
  return `Seen in ${seenIn.length} source${seenIn.length === 1 ? "" : "s"}: ${seenIn.map(entry => `${entry.label} ${entry.role}${entry.runBy ? `, run by ${entry.runBy}` : ""}`).join("; ")}`;
}
