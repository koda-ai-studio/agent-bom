/** The sample snapshot's ranked path collection, scoped and paginated like the API. */
export function queryStaticAttackPaths(graph, request) {
  const params = new URL(String(request), "https://demo.invalid").searchParams;
  const nodeId = params.get("node_id"), findingId = params.get("finding_id"), advisoryId = params.get("advisory_id");
  const carries = (path, wanted) => [...(path.vuln_ids ?? []), ...(path.finding_ids ?? []), ...path.hops]
    .some(value => String(value).toLowerCase() === wanted.toLowerCase() || String(value).toLowerCase().endsWith(`:${wanted.toLowerCase()}`));
  const candidates = (graph.attack_paths ?? []).filter(path => !nodeId || path.hops.includes(nodeId));
  let paths = candidates.filter(path => !findingId || carries(path, findingId));
  if (advisoryId && !findingId) paths = paths.filter(path => carries(path, advisoryId));
  // An advisory alias only resolves an occurrence when its own node is known.
  if (!paths.length && findingId && advisoryId && nodeId) paths = candidates.filter(path => carries(path, advisoryId));
  const offset = Math.max(0, Number(params.get("offset")) || 0);
  const limit = Math.min(200, Math.max(1, Number(params.get("limit")) || 75));
  return {...graph, attack_paths: paths.slice(offset, offset + limit),
    pagination: {total: paths.length, offset, limit, has_more: offset + limit < paths.length}};
}
