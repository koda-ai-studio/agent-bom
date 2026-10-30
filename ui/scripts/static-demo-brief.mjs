/** Compose the brief from the same labelled sample answers as the other demo views. */
export function buildStaticExecutiveBrief({ overview, posture, compliance, history, graph, tenantId, scanId, snapshotAt }) {
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  const allPaths = graph.attack_paths ?? [];
  const paths = allPaths.slice(0, 5).map(row => ({
    source: { id: row.source, label: nodes.get(row.source)?.label ?? row.source },
    target: { id: row.target, label: nodes.get(row.target)?.label ?? row.target },
    severity: row.severity ?? "unknown", reachability: row.reachability ?? "unknown",
  }));
  return {
    schema_version: "v1", document_type: "executive-brief", tenant_id: tenantId, generated_at: snapshotAt, sample_data: true,
    posture, issues: overview.issue_counts, remediation_priorities: (overview.top_risks ?? []).slice(0, 5),
    exposure_status: "available", exposure_paths: {
      schema_version: "v1", tool: "exposure_paths", tenant_id: tenantId, scan_id: scanId,
      snapshot_generation: graph.snapshot_generation ?? null, paths, count: paths.length,
      collection_coverage: { status: "unknown", reason: "Synthetic sample; no customer collection is established." },
      completeness: { status: paths.length === allPaths.length ? "complete" : "truncated", returned: paths.length, total: allPaths.length, reason: "sample_path_limit" },
    },
    compliance: { ...compliance, frameworks: compliance.frameworks ?? {} },
    scan_history: { ...history, data_points: (history.data_points ?? []).map(point => ({ ...point, comparison: point.comparison ?? { status: "not_comparable", reason: "Sample history does not record comparable scope." } })) },
    scope: { consistency: "independent_source_reads", remediation_basis: "overview.top_risks", exposure_basis: "sample_graph.attack_paths", exposure_scan_id: scanId, requested_priority_limit: 5 },
    links: { evidence_pack: "/v1/compliance/report/pack", verification_key: "/v1/compliance/verification-key", findings: "/v1/findings", exposure_paths: "/v1/graph/attack-paths" },
    evidence_boundary: "This unsigned sample brief summarizes synthetic technical evidence, not compliance attestation or confirmed exploitation. Sources retain independent scope. Recorded paths are not observed execution. The signed compliance pack is a separate artifact with its own verification requirements.",
  };
}
