import { describe, expect, it } from "vitest";

import { unknownGraphViewParam } from "@/lib/graph-view-params";
import { resolveSecurityGraphSurface } from "@/lib/security-graph-route";

const params = (query: string) => new URLSearchParams(query);

describe("graph view parameters", () => {
  it("accepts every lens, flow, step and map view the product links to", () => {
    for (const query of [
      "", "scan=s1", "lens=attack-path", "lens=estate&rollup=1", "lens=cloud", "lens=repository", "lens=identity",
      "lens=lineage", "lens=asset-drift", "lens=mesh", "lens=context&root=pkg%3Anext",
      "flow=auto", "flow=exposure", "flow=identity", "flow=vulnerability", "flow=inventory",
      "step=path", "step=impact", "step=owner", "step=fix", "step=verify", "step=expand", "map_view=full",
    ]) expect(unknownGraphViewParam(params(query)), query).toBeNull();
  });

  it("names the first parameter the graph cannot show instead of falling back silently", () => {
    expect(unknownGraphViewParam(params("lens=bogus"))).toEqual({ param: "lens", value: "bogus" });
    expect(unknownGraphViewParam(params("lens=estate&flow=sideways"))).toEqual({ param: "flow", value: "sideways" });
    expect(unknownGraphViewParam(params("step=deploy"))).toEqual({ param: "step", value: "deploy" });
    expect(unknownGraphViewParam(params("map_view=tiny"))).toEqual({ param: "map_view", value: "tiny" });
    expect(unknownGraphViewParam(params("lens=%20"))).toEqual({ param: "lens", value: " " });
  });

  it("routes an unknown lens or view to the not-found surface", () => {
    expect(resolveSecurityGraphSurface(params("lens=bogus"))).toBe("not-found");
    expect(resolveSecurityGraphSurface(params("lens=estate&flow=bogus"))).toBe("not-found");
    expect(resolveSecurityGraphSurface(params("lens=cloud"))).toBe("graph");
  });
});
