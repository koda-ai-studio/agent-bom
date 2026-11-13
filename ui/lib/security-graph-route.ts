import { unknownGraphViewParam } from "@/lib/graph-view-params";

export type SecurityGraphSurface = "estate" | "attack-path" | "graph" | "not-found";

/**
 * Resolve the composed investigation surface without treating a scan selector
 * as a different surface. Ranked exposure paths are the default; explicit
 * lenses preserve estate browsing and previously shared finding links. A lens
 * or view the graph does not have opens a not-found state, never another view.
 */
export function resolveSecurityGraphSurface(params: {
  get(name: string): string | null;
}): SecurityGraphSurface {
  if (unknownGraphViewParam(params)) return "not-found";
  const lens = params.get("lens")?.trim();
  if (lens === "attack-path") return "attack-path";
  if (lens === "estate") return "estate";
  if (lens) return "graph";

  return "attack-path";
}
