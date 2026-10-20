/** `name@version` for a finding's package; labels that already carry the version are kept as-is. */
export function packageVersionLabel(vuln: { packages: string[]; current_version?: string | undefined }): string {
  const name = vuln.packages[0] ?? "";
  const version = vuln.current_version?.trim();
  if (!name || !version) return name;
  return name.endsWith(`@${version}`) ? name : `${name}@${version}`;
}
