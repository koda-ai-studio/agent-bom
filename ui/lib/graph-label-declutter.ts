import type { Edge, Node } from "@xyflow/react";

const QUALIFIER_SEPARATOR = " · ";

function relationshipOf(edge: Edge): string {
  return typeof edge.data?.relationship === "string" ? edge.data.relationship : "";
}

/** Hide shared-server correlations only when their supporting server use is visible. */
export function hideRedundantDerivedEdges(
  edges: Edge[],
  nodes: Node[] = [],
  recordedEdges: readonly { id?: string; evidence?: Record<string, unknown> }[] = [],
): Edge[] {
  const servers = new Set(nodes.filter(node => !node.hidden && node.data.nodeType === "server").map(node => node.id));
  const uses = new Map<string, Set<string>>();
  for (const edge of edges) {
    if (edge.hidden || relationshipOf(edge) !== "uses" || !servers.has(edge.target)) continue;
    const targets = uses.get(edge.source) ?? new Set<string>();
    targets.add(edge.target);
    uses.set(edge.source, targets);
  }
  const evidenceById = new Map(recordedEdges.map(edge => [edge.id, edge.evidence]));
  return edges.filter(edge => {
    // Credential and other correlations need their own evidence proof; server
    // co-use or a common account is not enough to hide them.
    if (relationshipOf(edge) !== "shares_server") return true;
    const left = uses.get(edge.source), right = uses.get(edge.target);
    if (!left || !right) return true;
    const recordedServer = evidenceById.get(edge.id)?.server;
    if (typeof recordedServer === "string" && recordedServer) {
      return !(left.has(recordedServer) && right.has(recordedServer));
    }
    for (const server of left) if (right.has(server)) return false;
    return true;
  });
}

function splitLabel(label: string): { base: string; qualifier: string } {
  const at = label.lastIndexOf(QUALIFIER_SEPARATOR);
  return at < 0 ? { base: label, qualifier: "" } : { base: label.slice(0, at), qualifier: label.slice(at + QUALIFIER_SEPARATOR.length) };
}

/**
 * Show each repeated relationship once.
 *
 * Edges fanning out of (or into) one node with the same relationship and
 * qualifier keep a single visible caption, "Can Access ×6 · configured"; the others stay
 * quiet and reveal their own caption on hover, focus or selection.
 */
export function declutterRelationshipLabels(edges: Edge[]): Edge[] {
  // Cluster and aggregate links already carry their own counts.
  const labelled = edges.filter(edge => typeof edge.label === "string" && edge.label.length > 0 && !edge.hidden
    && !edge.data?.isClusterEdge && !edge.data?.aggregate);
  if (labelled.length < 2) return edges;
  const parts = new Map(labelled.map(edge => [edge.id, splitLabel(edge.label as string)]));

  const groupKey = (edge: Edge, side: "source" | "target") => {
    const part = parts.get(edge.id)!;
    return `${side}|${edge[side]}|${relationshipOf(edge) || part.base}|${part.qualifier}`;
  };
  const sizes = new Map<string, number>();
  for (const edge of labelled) for (const side of ["source", "target"] as const) {
    const key = groupKey(edge, side);
    sizes.set(key, (sizes.get(key) ?? 0) + 1);
  }
  // Each edge joins its larger group: a fan-out counts by source, a fan-in by target.
  const groups = new Map<string, Edge[]>();
  for (const edge of labelled) {
    const bySource = groupKey(edge, "source"), byTarget = groupKey(edge, "target");
    const key = sizes.get(bySource)! >= sizes.get(byTarget)! ? bySource : byTarget;
    groups.set(key, [...(groups.get(key) ?? []), edge]);
  }
  const replacements = new Map<string, Edge>();
  for (const members of groups.values()) {
    const ordered = [...members].sort((a, b) => a.id.localeCompare(b.id));
    const representative = ordered[Math.floor((ordered.length - 1) / 2)]!;
    for (const edge of ordered) {
      const { base, qualifier } = parts.get(edge.id)!;
      const count = ordered.length > 1 ? ` ×${ordered.length}` : "";
      // The evidence qualifier stays on every caption: a bare verb reads as observed fact.
      const text = `${base}${count}${qualifier ? `${QUALIFIER_SEPARATOR}${qualifier}` : ""}`;
      if (edge === representative) {
        replacements.set(edge.id, { ...edge, label: text });
      } else {
        const quiet: Edge = { ...edge, data: { ...edge.data, quietLabel: true } };
        delete quiet.label;
        replacements.set(edge.id, quiet);
      }
    }
  }
  return edges.map(edge => replacements.get(edge.id) ?? edge);
}
