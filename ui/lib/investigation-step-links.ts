import { remediationHref } from "@/lib/page-links";

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
