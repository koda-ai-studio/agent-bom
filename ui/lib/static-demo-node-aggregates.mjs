/** Answer a node-aggregates read from the demo's table of every node: the requested ids, the rest reported missing. */
export function queryStaticNodeAggregates(table, apiPath) {
  const params = new URL(apiPath, "http://demo").searchParams;
  const ids = [...new Set(params.getAll("node_id").map((id) => id.trim()).filter(Boolean))];
  const rows = new Map((table.aggregates ?? []).map((row) => [row.node_id, row]));
  return {
    ...table,
    scan_id: params.get("scan_id") || table.scan_id,
    snapshot_generation: params.get("snapshot_generation") || table.snapshot_generation || null,
    aggregates: ids.filter((id) => rows.has(id)).map((id) => rows.get(id)),
    missing_node_ids: ids.filter((id) => !rows.has(id)),
  };
}
