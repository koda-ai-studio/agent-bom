/**
 * Graph severity counts are issues (one advisory on one package counts once);
 * occurrences count every place it was found. Every number names its unit so
 * a graph total never reads as a different overview number.
 */

type IssueCounts = { issue_count?: number | undefined; finding_occurrence_count?: number | undefined };

const count = (value: number, singular: string, plural: string) => `${value.toLocaleString()} ${value === 1 ? singular : plural}`;

export function estateIssueLine(summary: IssueCounts | null | undefined): string | null {
  if (typeof summary?.issue_count !== "number") return null;
  const issues = count(summary.issue_count, "issue", "issues");
  return typeof summary.finding_occurrence_count === "number"
    ? `${issues} · ${count(summary.finding_occurrence_count, "occurrence", "occurrences")}`
    : issues;
}

const SCOPE_NOUN: Record<string, string> = { org: "org", organization: "org", account: "account", environment: "environment", subscription: "subscription", project: "project" };

/** A scope's own issues and occurrences: derived from the scope alone, so it never changes format as other data loads. */
export function scopeIssueLine(item: { entity_type: string; aggregate?: IssueCounts | undefined }): string | null {
  return estateIssueLine(item.aggregate);
}

/** The scope's share of the estate's issues, when it holds part of a known total. */
export function scopeIssueShare(item: { entity_type: string; aggregate?: IssueCounts | undefined }, estateIssues: number | undefined): string | undefined {
  const issues = item.aggregate?.issue_count;
  if (typeof issues !== "number" || typeof estateIssues !== "number" || issues >= estateIssues) return undefined;
  return `${issues.toLocaleString()} of ${count(estateIssues, "estate issue", "estate issues")} are in this ${SCOPE_NOUN[item.entity_type] ?? "scope"}`;
}

/** Context facts about a scope, minus any that only repeat its own name. */
export function scopeContextLine(item: { label: string; context?: Record<string, string> | undefined }): string | null {
  const label = item.label.trim().toLowerCase();
  const entries = Object.entries(item.context ?? {}).filter(([, value]) => String(value).trim().toLowerCase() !== label);
  return entries.length ? entries.map(([kind, value]) => `${kind}: ${value}`).join(" · ") : null;
}

type SeverityPair = { critical?: number | undefined; high?: number | undefined };
type EstateIssueBasis = { issue_count?: number | undefined; severity_counts?: SeverityPair | undefined };

/**
 * A scope that holds part of the estate, read against the estate-wide headline:
 * the critical/high that differ, and how many issues sit on entities outside it.
 */
export function scopeEstateComparison(
  item: { entity_type: string; aggregate?: (IssueCounts & { severity_counts?: SeverityPair | undefined }) | undefined },
  estate: EstateIssueBasis | null | undefined,
): string | null {
  const issues = item.aggregate?.issue_count;
  const total = estate?.issue_count;
  if (typeof issues !== "number" || typeof total !== "number" || issues >= total) return null;
  const noun = SCOPE_NOUN[item.entity_type] ?? "scope";
  const outside = `${(total - issues).toLocaleString()} of ${count(total, "issue", "issues")} ${total - issues === 1 ? "is" : "are"} outside this ${noun}`;
  const differing = (["critical", "high"] as const).filter((key) => (item.aggregate?.severity_counts?.[key] ?? 0) !== (estate?.severity_counts?.[key] ?? 0));
  if (!differing.length) return `${outside} (none critical or high)`;
  const pairs = differing.map((key) => `${(item.aggregate?.severity_counts?.[key] ?? 0).toLocaleString()} ${key} in this ${noun} · ${(estate?.severity_counts?.[key] ?? 0).toLocaleString()} estate-wide`);
  return `${pairs.join(" · ")} · ${outside}`;
}
