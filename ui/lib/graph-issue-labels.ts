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

/** A scope's issues; when it holds part of a known estate total, say "N of TOTAL issues in this org". */
export function scopeIssueLine(item: { entity_type: string; aggregate?: IssueCounts | undefined }, estateIssues: number | undefined): string | null {
  const issues = item.aggregate?.issue_count;
  if (typeof issues !== "number") return null;
  if (typeof estateIssues === "number" && issues < estateIssues) {
    return `${issues.toLocaleString()} of ${count(estateIssues, "issue", "issues")} in this ${SCOPE_NOUN[item.entity_type] ?? "scope"}`;
  }
  return estateIssueLine(item.aggregate);
}
