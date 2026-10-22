import { remediationHref } from "@/lib/page-links";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

/** Keep the selected occurrence; an advisory ID alone cannot identify a campaign. */
export function pathFindingId(path: AttackPath | null, nodes: UnifiedNode[], focusedFindingId?: string): string | undefined {
  if (focusedFindingId) return focusedFindingId;
  if (path?.finding_ids?.[0]) return path.finding_ids[0];
  const finding = nodes.find(node => node.entity_type === "vulnerability" || node.entity_type === "misconfiguration");
  const id = finding?.attributes?.finding_id;
  return typeof id === "string" && id ? id : undefined;
}

export function findingRemediationHref(findingId: string | undefined, scanId: string): string {
  return `${remediationHref({
    finding: findingId, view: "verification",
    scan: scanId && !scanId.startsWith("current-estate:") ? scanId : undefined,
  })}#campaigns`;
}

/** Strip the version from a package label: remediation rows are keyed by package name. */
export function packageNameFromLabel(label: string): string {
  const at = label.lastIndexOf("@");
  return at > 0 ? label.slice(0, at) : label;
}

/** Remediation for the path's package, pinned to a historical snapshot when one is selected. */
export function packageRemediationHref(packageLabel: string | undefined, scanId: string): string {
  return remediationHref({
    q: packageLabel ? packageNameFromLabel(packageLabel) : undefined,
    scan: scanId && !scanId.startsWith("current-estate:") ? scanId : undefined,
  });
}
