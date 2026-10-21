/** What a path's risk rests on when no finding is on it: the recorded reachability basis, never a severity. */
const BASIS_LABELS: Record<string, string> = {
  recorded_identifier_match: "Recorded identifier match",
  observed_graph_edges: "Observed graph edges",
  directed_provenance_backed_hops: "Provenance-backed hops",
  structural_topology_only: "Structural topology only",
  runtime_observed: "Observed at runtime",
};

export function pathHasFinding(path: { findings: string[]; hops: Array<{ role: string }> }): boolean {
  return path.findings.length > 0 || path.hops.some(hop => hop.role === "finding");
}

export function pathRiskBasisLabel(basis: readonly string[] | undefined): string {
  const first = basis?.find(Boolean);
  if (!first) return "Recorded relationships";
  return BASIS_LABELS[first] ?? first.replaceAll("_", " ").replace(/^./, letter => letter.toUpperCase());
}
