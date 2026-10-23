interface PackageVersionSource {
  packages: string[];
  current_version?: string | undefined;
  package_versions?: string[] | undefined;
  package_version_count?: number | undefined;
}

function bareName(label: string): string {
  const at = label.lastIndexOf("@");
  return at > 0 ? label.slice(0, at) : label;
}

/** `name@version` for a finding's package; labels that already carry the version are kept as-is. */
export function packageVersionLabel(vuln: PackageVersionSource): string {
  const name = vuln.packages[0] ?? "";
  const versionCount = Math.max(vuln.package_version_count ?? 0, vuln.package_versions?.length ?? 0);
  if (name && versionCount > 1) return `${bareName(name)} · ${versionCount} versions`;
  const version = vuln.current_version?.trim();
  if (!name || !version) return name;
  return name.endsWith(`@${version}`) ? name : `${name}@${version}`;
}
