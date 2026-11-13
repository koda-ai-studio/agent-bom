/** Every value the graph routes accept for their view parameters; anything else is a link the graph cannot show. */
const ALLOWED: Record<string, ReadonlySet<string>> = {
  lens: new Set(["attack-path", "estate", "cloud", "repository", "identity", "lineage", "asset-drift", "mesh", "context"]),
  flow: new Set(["auto", "exposure", "identity", "vulnerability", "inventory"]),
  // "expand" is a retired step name that older links still carry; it opens Impact.
  step: new Set(["path", "impact", "owner", "fix", "verify", "expand"]),
  map_view: new Set(["full"]),
};

/** The first view parameter whose value no graph view exists for, or null when every one is known. */
export function unknownGraphViewParam(params: { get(name: string): string | null }): { param: string; value: string } | null {
  for (const [param, allowed] of Object.entries(ALLOWED)) {
    const value = params.get(param);
    if (value !== null && !allowed.has(value)) return { param, value };
  }
  return null;
}
