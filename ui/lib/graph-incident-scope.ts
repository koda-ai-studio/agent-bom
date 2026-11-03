import type { GraphIncidentPage } from "@/lib/api-types";

/** Accept identity changes only when the API names the exact requested alias. */
export function incidentNodeMatches(page: GraphIncidentPage, requested: string): boolean {
  return page.node_id === requested || page.resolved_from === requested;
}

/** Reuse canonical IDs already resolved within this generation and owner scope. */
export function incidentCanonicalNode(pages: GraphIncidentPage[], requested: string): string {
  return pages.find(page => page.resolved_from === requested)?.node_id ?? requested;
}

/** Terminal paging is separate from missing endpoints, sampling and collection coverage. */
export function incidentPagesComplete(pages: GraphIncidentPage[]): boolean {
  const nodeIds = new Set(pages.flatMap(page => [page.node, ...page.nodes]).filter(Boolean).map(node => node!.id));
  const endpointsPresent = pages.every(page => page.edges.every(edge => nodeIds.has(edge.source) && nodeIds.has(edge.target)));
  return Boolean(endpointsPresent && pages.length && !pages.at(-1)?.next_cursor && pages.at(-1)?.completeness?.complete
    && pages.every(page => page.completeness && !page.completeness.sampled && page.completeness.missing_endpoint_count === 0
      && (page.completeness.complete || (page.next_cursor && page.completeness.reason === "page_limit"))));
}
