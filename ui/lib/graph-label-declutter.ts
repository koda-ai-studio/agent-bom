import type { Edge } from "@xyflow/react";

const QUALIFIER_SEPARATOR = " · ";

function relationshipOf(edge: Edge): string {
  return typeof edge.data?.relationship === "string" ? edge.data.relationship : "";
}

/**
 * Hide a derived ``shares_*`` link when the view already draws the shared
 * resource connected to both endpoints. The derived edge restates that fact,
 * adds a crossing line and distorts the layout ranks. It stays available when
 * the shared resource is not in view.
 */
export function hideRedundantDerivedEdges(edges: Edge[]): Edge[] {
  const neighbours = new Map<string, Set<string>>();
  for (const edge of edges) {
    if (relationshipOf(edge).startsWith("shares_")) continue;
    for (const [from, to] of [[edge.source, edge.target], [edge.target, edge.source]] as const) {
      const set = neighbours.get(from) ?? new Set<string>();
      set.add(to);
      neighbours.set(from, set);
    }
  }
  return edges.filter(edge => {
    if (!relationshipOf(edge).startsWith("shares_")) return true;
    const left = neighbours.get(edge.source), right = neighbours.get(edge.target);
    if (!left || !right) return true;
    for (const shared of left) if (right.has(shared)) return false;
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
