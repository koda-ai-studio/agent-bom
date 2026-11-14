import { findingsHref } from "./finding-issue-type";

/** Findings default to the last ~90 days so a count reads "last 90d", not "all"; 0 widens to all history. */
export const DEFAULT_FINDINGS_WINDOW_DAYS = 90;

/** Where the Overview Secrets chip links: every open secret finding in the default window. */
export const SECRET_FINDINGS_HREF = findingsHref({ scope: "all", issue: "secret" });

/**
 * The count-only read behind the Secrets chip. It is the Findings page's own query for
 * SECRET_FINDINGS_HREF (open, grouped issues, default window) with one row, so the chip
 * and the page it opens report the same total.
 */
export function secretFindingsTotalQuery() {
  return {
    findingClass: "secret" as const,
    windowDays: DEFAULT_FINDINGS_WINDOW_DAYS,
    groupOccurrences: true,
    approximateTotal: true,
    limit: 1,
  };
}
