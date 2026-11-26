import { expect, it } from "vitest";
import { emphasizedDisplayEdges } from "@/lib/graph-display-elements";

it("shows recorded direction in small views without assigning direction to undirected links", () => {
  const edges = ["directed", "undirected"].map(direction => ({ id: direction, source: "policy", target: "tool", data: { relationship: "manages", direction } }));
  const result = emphasizedDisplayEdges({ edges, nodes: [], neighborhood: null, pathEdgeIds: null, blastRadius: null, reachability: null, captureMode: false, zoom: 1 });
  expect(result[0]!.markerEnd).toBeDefined();
  expect(result[1]!.markerEnd).toBeUndefined();
});
