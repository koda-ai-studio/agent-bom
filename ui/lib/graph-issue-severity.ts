/** A finding count is coloured by its issues, never by a rated asset in the same scope. */
export function issueSeverity(aggregate?: { severity_counts?: Record<string, number> | undefined } | null): string | undefined {
  return ["critical", "high", "medium", "low"].find(severity => (aggregate?.severity_counts?.[severity] ?? 0) > 0);
}
