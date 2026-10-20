import type { GraphRollupAggregate, GraphRollupContainer } from "@/lib/api-types";

/**
 * Risk weights for ordering scopes. Contained critical findings dominate, then
 * known-exploited (when the API reports it), toxic combinations, internet
 * exposure and high findings. Size never ranks a scope.
 */
export const SCOPE_RISK_WEIGHTS = { critical: 100, kev: 50, toxic: 20, exposed: 10, high: 1 } as const;

const LEAF_SEVERITY_WEIGHT: Record<string, number> = { critical: SCOPE_RISK_WEIGHTS.critical, high: SCOPE_RISK_WEIGHTS.high };

const count = (aggregate: GraphRollupAggregate, key: string) => aggregate.severity_counts?.[key] ?? 0;

export function scopeRiskScore(item: GraphRollupContainer): number {
  const aggregate = item.aggregate;
  const kev = Number((aggregate as GraphRollupAggregate & { kev_count?: number }).kev_count ?? 0);
  const contained = count(aggregate, "critical") * SCOPE_RISK_WEIGHTS.critical + kev * SCOPE_RISK_WEIGHTS.kev +
    (aggregate.toxic_count || (aggregate.toxic_combo ? 1 : 0)) * SCOPE_RISK_WEIGHTS.toxic +
    (aggregate.exposed_count || (aggregate.internet_exposed ? 1 : 0)) * SCOPE_RISK_WEIGHTS.exposed +
    count(aggregate, "high") * SCOPE_RISK_WEIGHTS.high;
  const own = LEAF_SEVERITY_WEIGHT[(item.severity || "").toLowerCase()] ?? 0;
  return contained + own;
}

/** Highest contained risk first; ties keep the server's order. */
export function rankScopesByRisk<T extends GraphRollupContainer>(items: T[]): T[] {
  return items.map((item, index) => ({ item, index, score: scopeRiskScore(item) }))
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .map(entry => entry.item);
}

/** Scopes scoring at least half the highest score at this level. */
export function priorityScopes<T extends GraphRollupContainer>(items: T[]): T[] {
  const ranked = rankScopesByRisk(items);
  const top = ranked[0] ? scopeRiskScore(ranked[0]) : 0;
  if (top <= 0) return [];
  return ranked.filter(item => scopeRiskScore(item) >= top / 2);
}

export const IMAGE_GROUP_PREFIX = "image:";

function sumAggregates(items: GraphRollupContainer[]): GraphRollupAggregate {
  const severity: Record<string, number> = {};
  const byType: Record<string, number> = {};
  let descendants = 0, exposed = 0, toxic = 0, worstRank = 0, worst = "none";
  for (const item of items) {
    const aggregate = item.aggregate;
    descendants += aggregate.descendant_count + 1;
    exposed += aggregate.exposed_count;
    toxic += aggregate.toxic_count;
    for (const [key, value] of Object.entries(aggregate.severity_counts ?? {})) severity[key] = (severity[key] ?? 0) + value;
    for (const [key, value] of Object.entries(aggregate.by_type ?? {})) byType[key] = (byType[key] ?? 0) + value;
    byType[item.entity_type] = (byType[item.entity_type] ?? 0) + 1;
    if (aggregate.worst_severity_rank > worstRank) { worstRank = aggregate.worst_severity_rank; worst = aggregate.worst_severity; }
  }
  return {
    descendant_count: descendants, by_type: byType, severity_counts: severity, worst_severity: worst, worst_severity_rank: worstRank,
    internet_exposed: items.some(item => item.aggregate.internet_exposed), toxic_combo: items.some(item => item.aggregate.toxic_combo),
    exposed_count: exposed, toxic_count: toxic,
  };
}

/**
 * The image level between an environment and its packages. Packages that record
 * the image they were found in are grouped under one synthetic image row; the
 * group's counts are sums over the returned packages only.
 */
export function groupRollupByImage(items: GraphRollupContainer[]): { rows: GraphRollupContainer[]; images: Map<string, GraphRollupContainer[]> } {
  const images = new Map<string, GraphRollupContainer[]>();
  for (const item of items) {
    const image = item.entity_type === "package" ? item.context?.image : undefined;
    if (image) images.set(`${IMAGE_GROUP_PREFIX}${image}`, [...(images.get(`${IMAGE_GROUP_PREFIX}${image}`) ?? []), item]);
  }
  if (images.size === 0) return { rows: items, images };
  const rows: GraphRollupContainer[] = [];
  const emitted = new Set<string>();
  for (const item of items) {
    const image = item.entity_type === "package" ? item.context?.image : undefined;
    if (!image) { rows.push(item); continue; }
    const id = `${IMAGE_GROUP_PREFIX}${image}`;
    if (emitted.has(id)) continue;
    emitted.add(id);
    const members = images.get(id)!;
    const context = Object.fromEntries(Object.entries(item.context ?? {}).filter(([key]) => key !== "image")) as NonNullable<GraphRollupContainer["context"]>;
    rows.push({
      id, label: image, entity_type: "image", severity: "", is_container: true, has_children: true,
      direct_child_count: members.length, aggregate: sumAggregates(members), context,
      ...(item.cloud_provider ? { cloud_provider: item.cloud_provider, cloud_provider_basis: item.cloud_provider_basis } : {}),
    });
  }
  return { rows, images };
}
