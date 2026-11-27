/** Answer a node-aggregates read from the demo's table of every node: the requested ids, the rest reported missing. */
export function queryStaticNodeAggregates(table, apiPath) {
  const params = new URL(apiPath, "http://demo").searchParams;
  const ids = [...new Set(params.getAll("node_id").map((id) => id.trim()).filter(Boolean))];
  const rows = new Map((table.aggregates ?? []).map((row) => [row.node_id, row]));
  return {
    ...table,
    scan_id: params.get("scan_id") || table.scan_id,
    snapshot_generation: params.get("snapshot_generation") || table.snapshot_generation || null,
    aggregates: ids.filter((id) => rows.has(id)).map((id) => ({...rows.get(id),
      ...(table.scope_findings && table.scope_descendants ? {finding_disclosure: scopeFindingDisclosure(table, id, ids)} : {}),
    })),
    missing_node_ids: ids.filter((id) => !rows.has(id)),
  };
}

/** Use canonical issue keys and backend-generated containment, never equal counts as evidence of sharing. */
export function scopeFindingDisclosure(table, nodeId, requested) {
  const exclude_node_ids = requested.filter(id => id !== nodeId && table.scope_descendants[nodeId]?.includes(id)).sort();
  const excluded = new Set(exclude_node_ids.flatMap(id => (table.scope_findings[id] ?? []).map(row => row.issue_key)));
  const findings = (table.scope_findings[nodeId] ?? []).filter(row => !excluded.has(row.issue_key));
  return {issue_count: findings.length, severity_counts: findings.reduce((counts, row) => ({...counts, [row.severity]: (counts[row.severity] ?? 0) + 1}), {}), exclude_node_ids};
}

/** Exact server-derived issue groups for the selected immutable demo scope. */
export function queryStaticScopeFindings(table, apiPath) {
  const params = new URL(apiPath, "http://demo").searchParams;
  const nodeId = params.get("node_id");
  const scope = table.scopes?.[nodeId];
  if (!scope) throw new Error("No finding evidence was recorded for this demo scope.");
  const offset = Math.max(0, Number(params.get("offset")) || 0);
  const limit = Math.max(1, Math.min(100, Number(params.get("limit")) || 20));
  const excluded = new Set(params.getAll("exclude_node_id").flatMap(id => (table.scopes?.[id]?.findings ?? []).map(row => row.issue_key)));
  const findings = scope.findings.filter(row => !excluded.has(row.issue_key));
  return { ...scope, total: findings.length, offset, limit, findings: findings.slice(offset, offset + limit) };
}
