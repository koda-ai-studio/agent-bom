export const SEVERITY_ORDER: Readonly<Record<string, number>> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  informational: 1,
  none: 0,
  unknown: 0,
};

const SEVERITY_ALIASES: Readonly<Record<string, string>> = {
  informational: "info", moderate: "medium", important: "high", minor: "low", negligible: "low", unimportant: "low",
};

export function normalizeSeverity(severity: string | null | undefined): string {
  const raw = (severity ?? "").trim().toLowerCase();
  const key = SEVERITY_ALIASES[raw] ?? raw;
  return Object.hasOwn(SEVERITY_ORDER, key) ? key : "unknown";
}

export function severityRank(severity: string | null | undefined): number {
  return SEVERITY_ORDER[normalizeSeverity(severity)] ?? 0;
}

// Threshold semantics mirror core.severity.severity_policy_rank: INFO shares
// LOW's policy band and UNKNOWN is below NONE. Display sorting uses 0-5.
export function severityPolicyRank(severity: string | null | undefined): number {
  const key = normalizeSeverity(severity);
  if (key === "unknown") return -1;
  if (key === "none") return 0;
  return Math.max(1, severityRank(key) - 1);
}

// Literal class strings so Tailwind's source scan generates every utility.
const SEVERITY_CHIP_CLASS: Readonly<Record<string, string>> = {
  critical:
    "border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] text-[color:var(--severity-critical)]",
  high: "border-[color:var(--severity-high-border)] bg-[color:var(--severity-high-bg)] text-[color:var(--severity-high)]",
  medium:
    "border-[color:var(--severity-medium-border)] bg-[color:var(--severity-medium-bg)] text-[color:var(--severity-medium)]",
  low: "border-[color:var(--severity-low-border)] bg-[color:var(--severity-low-bg)] text-[color:var(--severity-low)]",
};

const NEUTRAL_CHIP_CLASS =
  "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]";

/** Theme-aware chip classes (text, tint, border) for a severity, from globals.css tokens. */
export function severityChipClass(severity: string | null | undefined): string {
  return SEVERITY_CHIP_CLASS[(severity ?? "").toLowerCase()] ?? NEUTRAL_CHIP_CLASS;
}

export function severityAtOrAbove(severity: string | null | undefined, threshold: string): boolean {
  return severityPolicyRank(severity) >= severityPolicyRank(threshold);
}
