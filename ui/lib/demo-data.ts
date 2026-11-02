/**
 * Whether the viewer is looking at labelled sample data: seeded demo sources
 * the server reports, or the screenshot capture mode that renders fixtures.
 * The "Demo data" banner and the identity chip both read this, so they cannot
 * disagree.
 */
export function hasDemoSeedSources(scanSources: readonly string[] | null | undefined): boolean {
  if (!scanSources?.length) return false;
  return scanSources.some((source) => source.includes("demo"));
}

export function isDemoDataView({ captureMode, scanSources }: { captureMode: boolean; scanSources?: readonly string[] | null | undefined }): boolean {
  return captureMode || hasDemoSeedSources(scanSources);
}
