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

it("branches the backend image entity right of its workload with its recorded sources", () => {
  const result = semanticGraphLayout([node("workload"), node("image")], [runs]);
  const image = result.nodes.find(n => n.id === "image")!, workload = result.nodes.find(n => n.id === "workload")!;
  expect(image.position.x).toBeGreaterThan(workload.position.x);
  expect(image.position.y).toBe(workload.position.y);
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

it("keeps image packages to the right of their image after spine placement", () => {
  const orchestrator = node("orchestrator", "agent");
  orchestrator.data.semanticLayer = "orchestration";
  const pkg = node("package", "package");
  pkg.data.semanticLayer = "package";
  const result = semanticGraphLayout([orchestrator, node("workload"), node("image"), pkg], [runs,
    { id: "package", source: "image", target: "package", data: { relationship: "contains" } },
  ], ["orchestrator", "workload"]);
  const x = (id: string) => result.nodes.find(n => n.id === id)!.position.x;
  expect(x("package")).toBeGreaterThan(x("image"));
  expect(x("image")).toBeGreaterThan(x("workload"));
});

import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { layoutAttackPathGraph } from "@/lib/attack-path-graph-layout";
it("retains the correlated image below a selected workload with its source chips", () => {
  const { graph, selected } = branchingFixture();
  const workload = { ...graph.nodes[0]!, id: "workload", entity_type: "container", semantic_layer: "app" };
  const image = { ...workload, id: "image", label: "sha256:image" };
  const target = { ...graph.nodes[0]!, id: "asset", entity_type: "data_store", semantic_layer: "asset" };
  const links = [{ ...graph.edges[0]!, id: "runs", source: "workload", target: "image", relationship: "runs", evidence: runs.data!.evidence as Record<string, unknown> },
    { ...graph.edges[0]!, id: "access", source: "workload", target: "asset", relationship: "can_access" }];
  const model = buildAttackPathGraphModel({ ...graph, nodes: [workload, image, target], edges: links, attack_paths: [] }, { ...selected, hops: ["workload", "asset"], edges: ["access"] });
  const chip = model.nodes.find(node => node.id === "image");
  expect(chip?.imageSubrow).toBe(true);
  expect(chip?.evidenceSources).toEqual(["sbom"]);
  const positions = layoutAttackPathGraph(model, "LR").positions;
  expect(positions.get("image")!.x).toBe(positions.get("workload")!.x);
  expect(positions.get("image")!.y).toBeGreaterThan(positions.get("workload")!.y);
});
