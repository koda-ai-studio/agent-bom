export type IssueTypeFilter = "all" | "vulnerability" | "misconfiguration" | "secret" | "pii" | "identity" | "unclassified";

export type IssueType = Exclude<IssueTypeFilter, "all">;

export type SeverityBand = "critical" | "high" | "medium" | "low";

export type SeverityBucket = Record<SeverityBand, number>;

export type IssueSeverityMatrix = Record<IssueType, SeverityBucket> & {
  totals: SeverityBucket;
  byType: Record<IssueType, number>;
  openTotal: number;
};

export const ISSUE_TYPE_FILTERS: { key: IssueTypeFilter; label: string; hint: string }[] = [
  { key: "all", label: "All types", hint: "Every issue class" },
  { key: "vulnerability", label: "Vulnerabilities", hint: "CVE / package risk" },
  { key: "misconfiguration", label: "Misconfigurations", hint: "Cloud, IaC, policy" },
  { key: "secret", label: "Secrets", hint: "Exposed credentials" },
  { key: "pii", label: "Personal data", hint: "Personal data in source" },
  { key: "identity", label: "Identity", hint: "IAM / NHI exposure" },
  { key: "unclassified", label: "Unclassified", hint: "Needs taxonomy review" },
];

export const ISSUE_TYPE_SHORT: Record<IssueType, string> = {
  vulnerability: "CVE",
  misconfiguration: "Misconfig",
  secret: "Secret",
  pii: "Personal",
  identity: "Identity",
  unclassified: "Other",
};

export const SEVERITY_BANDS: SeverityBand[] = ["critical", "high", "medium", "low"];

export function emptySeverityBucket(): SeverityBucket {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

export function emptyIssueSeverityMatrix(): IssueSeverityMatrix {
  return {
    vulnerability: emptySeverityBucket(),
    misconfiguration: emptySeverityBucket(),
    secret: emptySeverityBucket(),
    pii: emptySeverityBucket(),
    identity: emptySeverityBucket(),
    unclassified: emptySeverityBucket(),
    totals: emptySeverityBucket(),
    byType: { vulnerability: 0, misconfiguration: 0, secret: 0, pii: 0, identity: 0, unclassified: 0 },
    openTotal: 0,
  };
}

export function findingsHref(opts: {
  scope?: "latest" | "all";
  severity?: SeverityBand | "all";
  issue?: IssueTypeFilter;
  kev?: boolean;
}): string {
  const params = new URLSearchParams();
  if (opts.scope === "all") params.set("scope", "all");
  if (opts.severity && opts.severity !== "all") params.set("severity", opts.severity);
  if (opts.issue && opts.issue !== "all") params.set("issue", opts.issue);
  if (opts.kev) params.set("kev", "1");
  const qs = params.toString();
  return qs ? `/findings?${qs}` : "/findings";
}
