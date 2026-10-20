const FINDING_TYPES = new Set(["vulnerability", "misconfiguration", "driftIncident"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);

interface TooltipInput {
  label: string;
  nodeType: string;
  severity?: string | undefined;
  cvssScore?: number | undefined;
  epssScore?: number | undefined;
  isKev?: boolean | undefined;
}

/** A finding's recorded severity, or undefined when it was never rated. */
export function findingSeverity(data: Pick<TooltipInput, "nodeType" | "severity">): string | undefined {
  if (!FINDING_TYPES.has(data.nodeType)) return undefined;
  const severity = (data.severity ?? "").trim().toLowerCase();
  return SEVERITIES.has(severity) ? severity : undefined;
}

/**
 * Hover text for a canvas node. Scores stay off the canvas so a finding shows
 * its severity once (the ring); the exact CVSS, EPSS and KEV facts live here
 * and in the inspector.
 */
export function graphNodeTooltip(data: TooltipInput): string {
  const parts = [data.label];
  const severity = findingSeverity(data);
  if (severity) parts.push(`${severity.charAt(0).toUpperCase()}${severity.slice(1)} severity`);
  else if (FINDING_TYPES.has(data.nodeType)) parts.push("Severity not rated");
  if (typeof data.cvssScore === "number" && Number.isFinite(data.cvssScore)) parts.push(`CVSS ${data.cvssScore.toFixed(1)}`);
  if (typeof data.epssScore === "number" && Number.isFinite(data.epssScore)) parts.push(`EPSS ${(data.epssScore * 100).toFixed(1)}%`);
  if (data.isKev) parts.push("CISA KEV");
  return parts.join(" · ");
}
