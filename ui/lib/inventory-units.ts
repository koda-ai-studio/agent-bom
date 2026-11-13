import type { InventorySummaryResponse } from "@/lib/api";
import type { AssetKindConfig } from "@/lib/inventory";

/**
 * Asset kinds group several graph entity types, and those types are different
 * units (an MCP server, the tools it exposes, and individual tool calls). A
 * kind headline counts only its primary unit; every other type is reported as
 * its own count so no number ever adds unlike things together.
 */

const TYPE_LABELS: Record<string, readonly [singular: string, plural: string]> = {
  server: ["MCP server", "MCP servers"],
  tool_call: ["tool call", "tool calls"],
  agent: ["AI agent", "AI agents"],
  container: ["container image", "container images"],
  api_gateway: ["API gateway", "API gateways"],
  org: ["organization", "organizations"],
  credential_ref: ["credential reference", "credential references"],
  ci_job: ["CI job", "CI jobs"],
};

export function entityTypeLabel(entityType: string, count: number): string {
  const known = TYPE_LABELS[entityType];
  if (known) return count === 1 ? known[0] : known[1];
  const singular = entityType.replace(/_/g, " ");
  if (count === 1) return singular;
  return /[^aeiou]y$/.test(singular) ? `${singular.slice(0, -1)}ies` : `${singular}s`;
}

export function capitalize(text: string): string {
  return text ? `${text.charAt(0).toUpperCase()}${text.slice(1)}` : text;
}

export interface TypeCount {
  type: string;
  count: number;
}

export interface KindHeadline {
  /** Count of the kind's primary unit only. */
  primary: number;
  /** Non-zero counts for the kind's other entity types, largest first. */
  breakdown: (TypeCount & { label: string })[];
}

export function kindHeadline(kind: AssetKindConfig, byType: Readonly<Record<string, number>>): KindHeadline {
  const primary = kind.primaryTypes.reduce((total, type) => total + (byType[type] ?? 0), 0);
  const breakdown = kind.entityTypes
    .filter((type) => !kind.primaryTypes.includes(type) && (byType[type] ?? 0) > 0)
    .map((type) => ({ type, count: byType[type]!, label: entityTypeLabel(type, byType[type]!) }))
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
  return { primary, breakdown };
}

export function formatBreakdown(breakdown: KindHeadline["breakdown"]): string {
  return breakdown.map((part) => `${part.count.toLocaleString()} ${part.label}`).join(" · ");
}

/** Accessible card name that states every unit, e.g. "Servers & tools: 12 MCP servers, plus 312 tools, in snapshot". */
export function kindCardLabel(
  kind: AssetKindConfig,
  primary: number,
  breakdown: KindHeadline["breakdown"],
  scopeCaption: string,
): string {
  const parts = breakdown.map((part) => `${part.count.toLocaleString()} ${part.label}`);
  const others = parts.length <= 2 ? parts.join(" and ") : `${parts.slice(0, -1).join(", ")}, and ${parts.at(-1)}`;
  const also = others ? `, plus ${others}` : "";
  return `${kind.label}: ${primary.toLocaleString()} ${kindUnit(kind, primary)}${also}, ${scopeCaption}`;
}

/** The kind's headline unit, singular for exactly one. */
export function kindUnit(kind: AssetKindConfig, count: number): string {
  return count === 1 ? capitalize(kind.singular) : kind.unitLabel;
}

/**
 * Per-type counts for one kind at the current filters, independent of any
 * selected type. The summary's type facet is self-excluding (it applies every
 * filter except type), so it keeps sibling counts visible after a type is
 * picked; with no type selected it equals `by_type`.
 */
export function kindTypeCounts(kind: AssetKindConfig, summary: InventorySummaryResponse): TypeCount[] {
  const buckets = summary.facets?.type?.buckets;
  const counts = new Map<string, number>();
  if (buckets && buckets.length > 0) {
    for (const bucket of buckets) if (bucket.value) counts.set(bucket.value, bucket.count);
  } else {
    for (const [type, count] of Object.entries(summary.by_type)) counts.set(type, count);
  }
  return kind.entityTypes.map((type) => ({ type, count: counts.get(type) ?? 0 }));
}
