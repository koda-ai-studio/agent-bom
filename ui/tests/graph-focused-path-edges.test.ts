import { describe, expect, it } from "vitest";
import type { Edge } from "@xyflow/react";
import { emphasizedDisplayEdges } from "@/lib/graph-display-elements";

describe("focused path edges", () => {
  it("leave the overview layout's handle sides, arcs and end fans behind when the path is re-placed in hop order", () => {
    const edge: Edge = { id: "role->agent", source: "role", target: "agent", type: "compact", sourceHandle: "context", targetHandle: "context",
      data: { relationship: "can_access", arcDy: [40, 40], sourceFan: 7, targetFan: -7, passesBehind: true } };
    const [shown] = emphasizedDisplayEdges({ edges: [edge], nodes: [], neighborhood: null, pathEdgeIds: new Set([edge.id]),
      blastRadius: null, reachability: null, captureMode: true, zoom: 1 });
    expect(shown!.sourceHandle).toBeNull();
    expect(shown!.targetHandle).toBeNull();
    expect(shown!.data).toMatchObject({ relationship: "can_access", pathEmphasis: true });
    for (const key of ["arcDy", "sourceFan", "targetFan", "passesBehind"]) expect(shown!.data).not.toHaveProperty(key);
  });
});
