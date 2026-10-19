import { api } from "@/lib/api";
import type { UnifiedNode } from "@/lib/graph-schema";

export interface EntitySearchResult {
  key: string;
  label: string;
  kind: string;
  href: string;
}

export const ENTITY_SEARCH_TYPES = ["vulnerability", "agent", "package", "server"] as const;
export const ENTITY_SEARCH_LIMIT = 8;

const CVE = /\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})\b/i;

function neighbourhoodHref(nodeId: string): string {
  return `/security-graph?${new URLSearchParams({ lens: "lineage", investigate: "1", root: nodeId, node: nodeId })}`;
}

function graphHref(nodeId: string): string {
  return `/security-graph?${new URLSearchParams({ lens: "attack-path", node: nodeId })}`;
}

/** Map graph search hits to palette rows; advisory occurrences collapse onto their advisory. */
export function entitySearchResults(nodes: readonly UnifiedNode[]): EntitySearchResult[] {
  const results = new Map<string, EntitySearchResult>();
  for (const node of nodes) {
    const type = String(node.entity_type);
    if (type === "vulnerability") {
      const advisory = String(node.label).match(CVE)?.[0] ?? String(node.label);
      const key = `cve:${advisory}`;
      if (!results.has(key)) results.set(key, { key, label: advisory, kind: "Advisory", href: `/findings?${new URLSearchParams({ q: advisory })}` });
    } else if (type === "agent") {
      // Graph labels are display names and estate agents may have no inventory page; the neighbourhood always resolves.
      results.set(node.id, { key: node.id, label: node.label, kind: "Agent", href: neighbourhoodHref(node.id) });
    } else if (type === "package") {
      // Occurrences of one package version share a label; the first opens its paths.
      const key = `package:${node.label}`;
      if (!results.has(key)) results.set(key, { key, label: node.label, kind: "Package", href: graphHref(node.id) });
    } else if (type === "server") {
      results.set(node.id, { key: node.id, label: node.label, kind: "MCP server", href: graphHref(node.id) });
    }
  }
  return [...results.values()];
}

/**
 * Bounded entity search over the current tenant estate: a few hits per type so
 * one advisory's many occurrences cannot crowd agents and packages out.
 */
export async function searchEstateEntities(query: string): Promise<EntitySearchResult[]> {
  const perType = Math.max(2, Math.ceil(ENTITY_SEARCH_LIMIT / ENTITY_SEARCH_TYPES.length));
  const settled = await Promise.allSettled(
    ENTITY_SEARCH_TYPES.map((type) => api.searchGraph(query, { entityTypes: [type], limit: perType })),
  );
  const fulfilled = settled.flatMap((result) => (result.status === "fulfilled" ? [result.value] : []));
  if (!fulfilled.length) throw new Error("Entity search is unavailable");
  return entitySearchResults(fulfilled.flatMap((response) => response.results)).slice(0, ENTITY_SEARCH_LIMIT);
}
