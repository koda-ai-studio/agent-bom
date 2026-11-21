import type { Edge, Node } from "@xyflow/react";
import { expect, it } from "vitest";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";

const node = (id: string, entityType = "container"): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 },
  data: { label: id, nodeType: "container", entityType, semanticLayer: "infra" } });
const runs: Edge = { id: "runs", source: "workload", target: "image", data: { relationship: "runs", evidence: {
  source: "image-digest-correlation", tier: "derived", basis: "image_digest_match",
  workload_sources: ["kubernetes"], image_sources: ["sbom"],
} } };

it("preserves runs evidence through the real API-to-canvas adapter", () => {
  const { graph } = branchingFixture();
  const nodes = ["workload", "image"].map(id => ({ ...graph.nodes[0]!, id, entity_type: "container", semantic_layer: "infra" }));
  const edge = { ...graph.edges[0]!, id: "runs", source: "workload", target: "image", relationship: "runs", evidence: runs.data!.evidence as Record<string, unknown> };
  const flow = buildUnifiedFlowGraph({ ...graph, nodes, edges: [edge], attack_paths: [] }, createExpandedGraphFilters());
  expect(flow.edges.find(e => e.id === "runs")?.data?.evidence).toEqual(edge.evidence);
  const placed = semanticGraphLayout(flow.nodes, flow.edges);
  expect(placed.nodes.find(n => n.id === "image")?.data.evidenceSources).toEqual(["sbom"]);
});

it("keeps the backend image entity below its workload with recorded source chips", () => {
  const result = semanticGraphLayout([node("workload"), node("image")], [runs]);
  const image = result.nodes.find(n => n.id === "image")!, workload = result.nodes.find(n => n.id === "workload")!;
  expect(image.position.x).toBe(workload.position.x);
  expect(image.position.y).toBeGreaterThan(workload.position.y);
  expect(image.data.imageSubrow).toBe(true);
  expect(image.data.evidenceSources).toEqual(["sbom"]);
  expect(workload.data.evidenceSources).toEqual(["kubernetes"]);
  expect(result.edges[0]!.source).toBe("workload");
  expect(result.edges[0]!.target).toBe("image");
});

it("does not turn CI job runs into image subrows", () => {
  const result = semanticGraphLayout([node("workload", "ci_job"), node("image")], [runs]);
  expect(result.nodes.every(n => !n.data.imageSubrow)).toBe(true);
});

it("keeps an explicit image hop on the selected spine", () => {
  const result = semanticGraphLayout([node("workload"), node("image")], [runs], ["workload", "image"]);
  const image = result.nodes.find(n => n.id === "image")!, workload = result.nodes.find(n => n.id === "workload")!;
  expect(image.position.x).toBeGreaterThan(workload.position.x);
  expect(image.position.y).toBe(workload.position.y);
  expect(image.data.imageSubrow).not.toBe(true);
});

it("keeps image packages in the owner's final column after spine placement", () => {
  const orchestrator = node("orchestrator", "agent");
  orchestrator.data.semanticLayer = "orchestration";
  const pkg = node("package", "package");
  pkg.data.semanticLayer = "package";
  const result = semanticGraphLayout([orchestrator, node("workload"), node("image"), pkg], [runs,
    { id: "package", source: "image", target: "package", data: { relationship: "contains" } },
  ], ["orchestrator", "workload"]);
  const x = (id: string) => result.nodes.find(n => n.id === id)!.position.x;
  expect(x("package")).toBe(x("image"));
  expect(x("image")).toBe(x("workload"));
});
