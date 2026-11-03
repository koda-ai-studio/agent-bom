import { describe, expect, it } from "vitest";
import { emphasizedDisplayEdges } from "@/lib/graph-display-elements";

describe("grouped navigation during reachability inspection", () => {
  it("keeps the remainder connected without claiming an aggregate is a traversable path", () => {
    const edges = [
      { id: "named", source: "root", target: "named", data: { relationship: "uses", traversable: true } },
      { id: "rest", source: "root", target: "rest", data: { relationship: "uses", isClusterEdge: true, traversable: false, members: ["hidden"] } },
      { id: "unrelated", source: "other", target: "outside" },
    ];
    const result = emphasizedDisplayEdges({
      edges, nodes: [], neighborhood: null, pathEdgeIds: null, blastRadius: null, captureMode: true, zoom: 0.5,
      reachability: { rootId: "root", rootLabel: "Root", truncated: false, nodeIds: new Set(["root", "named", "hidden"]),
        edgeKeys: new Set(["root=>named", "root=>hidden"]), countsByType: {}, pathPreviews: [] },
    });
    expect(result[1]!.style?.opacity).toBeGreaterThanOrEqual(0.8);
    expect(result[1]!.data).toMatchObject({ traversable: false, directionEmphasis: false, members: ["hidden"] });
    expect(result[1]!.style?.filter).toBeUndefined();
    expect(result[2]!.style?.opacity).toBeLessThan(0.1);
  });
});
