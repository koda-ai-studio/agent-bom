import type { IssueSeverityCounts } from "@/lib/api-types";

type SeverityCounts = Pick<IssueSeverityCounts, "critical" | "high" | "medium" | "low" | "total">;

export function openIssueSeverity(
  source: (SeverityCounts & { issues?: IssueSeverityCounts | undefined }) | null | undefined,
): SeverityCounts | null {
  if (!source) return null;
  // A bounded issue walk is a lower bound; the occurrence histogram beside it is exact.
  return source.issues && !source.issues.approximate ? source.issues : source;
}
