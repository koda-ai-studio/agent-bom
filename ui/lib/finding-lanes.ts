export const FINDING_LANES = [
  { key: "vulnerabilities", label: "Vulnerabilities", hint: "Package and code weaknesses, malicious artifacts, and observed attacks." },
  { key: "cloud", label: "Cloud config", hint: "Failed and unevaluated cloud checks, grouped by provider and control." },
  { key: "iac", label: "IaC", hint: "Infrastructure templates: repository file, line, rule, and fix." },
  { key: "secrets", label: "Secrets", hint: "Credential exposures by affected asset." },
  { key: "identity", label: "Identity", hint: "Identity and permission findings by principal." },
  { key: "data", label: "Data", hint: "Sensitive and personal data exposures by resource." },
  { key: "other", label: "Other", hint: "Runtime, policy, and unclassified findings outside these lanes." },
  { key: "all", label: "All findings", hint: "Cross-lane risk queue." },
] as const;
export type FindingLane = typeof FINDING_LANES[number]["key"];
export function initialFindingLane(lane: string | null, legacyIssue: string | null, hasDeepLink: boolean): FindingLane {
  if (FINDING_LANES.some((item) => item.key === lane)) return lane as FindingLane;
  return legacyIssue || hasDeepLink ? "all" : "vulnerabilities";
}
