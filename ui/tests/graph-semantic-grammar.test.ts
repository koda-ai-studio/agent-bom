import { GRAPH_SEMANTIC_LAYER_META } from "@/lib/graph-schema.generated";
import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
import { relationshipLaneFor } from "@/lib/relationship-lanes";
import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";

const node = (id: string, nodeType: LineageNodeData["nodeType"], surface?: string): Node<LineageNodeData> => ({
  id, position: { x: 0, y: 0 }, data: { label: id, nodeType, semanticLayer: ({ user: "user", container: "app", agent: "orchestration", server: "mcp_server", tool: "tool", credential: "identity", package: "package" } as Record<string, string>)[nodeType], ...(surface ? { dimensions: { surface } } : {}) },
});

describe("shared semantic graph grammar", () => {
  it("uses backend layers even without topology to rank a mixed graph", () => {
    const nodes = [node("person", "user"), node("workload", "container"), node("agent", "agent"),
      node("server", "server"), node("tool", "tool"), node("credential", "credential")];
    const { nodes: placed } = graphHierarchyLayout(nodes, []);
    const x = new Map(placed.map(n => [n.id, n.position.x]));
    expect(x.get("person")).toBeLessThan(x.get("workload")!);
    expect(x.get("workload")).toBeLessThan(x.get("agent")!);
    expect(x.get("agent")).toBeLessThan(x.get("server")!);
    expect(x.get("server")).toBeLessThan(x.get("tool")!);
    expect(x.get("tool")).toBe(x.get("credential"));
  });

  it("honours the backend semantic_layer over the surface and renderer kind", () => {
    const entry = node("entry", "container", "container-image");
    entry.data.semanticLayer = "user";
    const { nodes } = graphHierarchyLayout([entry, node("agent", "agent")], []);
    expect(nodes[0]!.position.x).toBe(GRAPH_SEMANTIC_LAYER_META.user.column * 380);
    expect(nodes[1]!.position.x).toBeGreaterThan(nodes[0]!.position.x);
  });

  it("surfaces an invalid backend layer instead of guessing a column", () => {
    const bad = node("bad", "container");
    bad.data.semanticLayer = "not-a-layer";
    const result = graphHierarchyLayout([bad], []);
    expect(result.nodes[0]!.data.semanticLayerIssue).toBe("Semantic layer unavailable");
    expect(result.nodes[0]!.position.x).toBeGreaterThan(5 * 380);
  });

  it("surfaces a missing API layer without deriving it from the entity type", () => {
    const bad = node("bad", "container");
    bad.data.entityType = "container";
    bad.data.semanticLayer = undefined;
    const result = graphHierarchyLayout([bad], []);
    expect(result.nodes[0]!.data.semanticLayerIssue).toBe("Semantic layer unavailable");
    expect(result.nodes[0]!.position.x).toBeGreaterThan(5 * 380);
  });

  it("keeps separate incoming ports for different sources of the same relationship", () => {
    const edges: Edge[] = ["developer", "sre"].map(source => ({ id: source, source, target: "server", data: { relationship: "uses" } }));
    const y = (id: string) => id === "developer" ? 0 : id === "sre" ? 200 : 100;
    const first = relationshipLaneFor("developer", edges, y, id => id === "server" ? 400 : 0);
    const second = relationshipLaneFor("sre", edges, y, id => id === "server" ? 400 : 0);
    expect(first.target).not.toBe(second.target);
  });

  it("draws a selected path's terminal CVE as a hop", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const terminal = selected.hops.at(-1)!;
    expect(terminal).toBe("cve:next");
    expect(model.pathNodeIds.at(-1)).toBe(terminal);
    expect(model.nodes.find(n => n.id === terminal)?.role).toBe("target");
  });
});

import { mcpEvidenceFlow } from "@/lib/graph-mcp-flow";
import { cloudHierarchyLayout } from "@/lib/graph-cloud-hierarchy";
import { mixedEvidenceFlow } from "@/lib/graph-mixed-flow";
import { investigationFlow } from "@/lib/graph-investigation-flow";
import { relationshipPath } from "@/lib/relationship-routing";
import { Position } from "@xyflow/react";
import { semanticColumns } from "@/lib/graph-semantic-columns";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { hopColumnLayout } from "@/lib/graph-hop-columns";
import { layoutAttackPathGraph } from "@/lib/attack-path-graph-layout";

it("keeps a vertical mobile spine and symmetric desktop sibling lanes", () => {
  const { graph, selected } = branchingFixture();
  const model = buildAttackPathGraphModel(graph, selected);
  const desktop = layoutAttackPathGraph(model, "LR"), mobile = layoutAttackPathGraph(model, "TB");
  expect(desktop.direction).toBe("LR");
  expect(mobile.direction).toBe("TB");
  expect(new Set(model.pathNodeIds.map(id => mobile.positions.get(id)!.x)).size).toBe(1);
  const branches = ["a", "b"].map(id => ({ ...model.nodes[0]!, id, role: "branch" as const, semanticLayer: "mcp_server" }));
  const paired = layoutAttackPathGraph({ ...model, nodes: [...model.nodes.filter(n => model.pathNodeIds.includes(n.id)), ...branches], edges: [] }, "LR");
  expect(paired.lanes.get("a")).toBe(-paired.lanes.get("b")!);
});

it("retains backend columns even when a selected spine traverses them in reverse", () => {
  const nodes = [node("asset", "package"), node("server", "server"), node("tool", "tool")];
  const columns = semanticColumns(nodes, [{ source: "server", target: "tool", data: { relationship: "exposes" } }], ["asset", "server"]);
  expect(columns.get("server")).toBe(GRAPH_SEMANTIC_LAYER_META.mcp_server.column);
  expect(columns.get("asset")).toBe(GRAPH_SEMANTIC_LAYER_META.package.column);
  expect(columns.get("tool")).toBeGreaterThan(columns.get("server")!);
});

it("keeps sibling context below the highlighted top path", () => {
  const nodes = [node("root", "agent"), node("left", "server"), node("right", "server")];
  const edges = ["left", "right"].map(id => ({ id, source: "root", target: id, data: { relationship: "uses" } }));
  const result = semanticGraphLayout(nodes, edges, ["root"]);
  const left = result.nodes.find(n => n.id === "left")!, right = result.nodes.find(n => n.id === "right")!;
  expect(left.position.y).toBeGreaterThan(0);
  expect(right.position.y).toBeGreaterThan(left.position.y);
});

it("keeps semantic columns and the straight spine through mobile preview placement", () => {
  const nodes = [node("person", "user"), node("server", "server")];
  const edges = [{ id: "uses", source: "person", target: "server" }];
  const placed = semanticGraphLayout(nodes, edges, ["person", "server"]).nodes;
  expect(hopColumnLayout(placed, edges, "person", { columnGap: 120, rowGap: 240, vertical: true }).map(n => n.position))
    .toEqual(placed.map(n => n.position));
});

it.each([mcpEvidenceFlow, cloudHierarchyLayout, mixedEvidenceFlow])("uses the same columns through every layout entry point", layout => {
  const nodes = [node("person", "user"), node("agent", "agent"), node("server", "server")];
  expect(layout(nodes, [])?.nodes.map(n => n.position)).toEqual(graphHierarchyLayout(nodes, []).nodes.map(n => n.position));
});

it("investigation flows preserve semantic columns", () => {
  const nodes = [node("person", "user"), node("identity", "credential")];
  const edges = [{ id: "uses", source: "person", target: "identity", data: { relationship: "authenticates_as" } }];
  const result = investigationFlow(nodes, edges, "identity");
  expect(result.nodes.find(n => n.id === "identity")?.position.x).toBe(graphHierarchyLayout(nodes, edges).nodes[1]!.position.x);
});

it("investigation highlights only the server-ranked spine rather than deriving a path", () => {
  const nodes = [node("person", "user"), node("identity", "credential"), node("tool", "tool")];
  nodes[0]!.data.semanticPathIndex = 0;
  nodes[2]!.data.semanticPathIndex = 1;
  const edges = [{ id: "uses", source: "person", target: "identity", data: { relationship: "authenticates_as" } },
    { id: "tool", source: "person", target: "tool", data: { relationship: "uses" } }];
  expect(investigationFlow(nodes, edges, "identity").primaryPath).toEqual(["person", "tool"]);
  expect(investigationFlow(nodes.map(n => ({ ...n, data: { ...n.data, semanticPathIndex: undefined } })), edges, "identity").primaryPath).toEqual([]);
});

it("routes relationships as independent cubic curves without shared straight trunks", () => {
  const edge = { source: "a", target: "b", sourceX: 72, sourceY: 40, targetX: 480, targetY: 240,
    sourcePosition: Position.Right, targetPosition: Position.Left };
  const [path] = relationshipPath(edge, [], { source: 0, target: -7 });
  expect(path).toMatch(/C/);
  expect(path).not.toMatch(/[LQ]/);
});

it("never infers a missing semantic layer from a renderer", () => {
  const missing = node("legacy", "server");
  missing.data.semanticLayer = undefined;
  const result = graphHierarchyLayout([missing], []);
  expect(result.nodes[0]!.data.semanticLayerIssue).toBe("Semantic layer unavailable");
});

it("does not move backend columns to match relationship depth", () => {
  const workload = node("workload", "container");
  workload.data.semanticLayer = "app";
  const identity = node("identity", "credential");
  identity.data.semanticLayer = "identity";
  expect(semanticColumns([workload, identity], [{ source: "identity", target: "workload" }]).get("workload")).toBe(GRAPH_SEMANTIC_LAYER_META.app.column);
});

it("keeps same-layer path hops distinct within their backend column", () => {
  const nodes = [node("first", "server"), node("second", "server"), node("tool", "tool")];
  const result = semanticGraphLayout(nodes, [], ["first", "second", "tool"]);
  const [first, second, tool] = result.nodes;
  expect(first!.position.y).toBe(second!.position.y);
  expect(second!.position.y).toBe(tool!.position.y);
  expect(first!.position.x).toBeLessThan(second!.position.x);
  expect(second!.position.x).toBeLessThan(tool!.position.x);
});

it("frames the occupied selected-path columns without a blank leading canvas", () => {
  const { graph, selected } = branchingFixture();
  const model = buildAttackPathGraphModel(graph, selected);
  const layout = layoutAttackPathGraph(model, "LR");
  const xs = [...layout.positions.values()].map(point => point.x);
  expect(Math.min(...xs)).toBe(0);
  expect(layout.width).toBe(Math.max(...xs) + layout.nodeWidth);
});

it("places a recorded package dependency below its single server owner", () => {
  const input = [node("server", "server"), node("package", "package")];
  const edge = { id: "dependency", source: "server", target: "package", data: { relationship: "depends_on" } };
  const result = graphHierarchyLayout(input, [edge]);
  expect(result.nodes[1]!.position.x).toBe(result.nodes[0]!.position.x);
  expect(result.nodes[1]!.position.y).toBeGreaterThan(result.nodes[0]!.position.y);
  expect(result.nodes[1]!.data.semanticOwner).toBe("server");
  expect(result.edges[0]).toMatchObject({ source: "server", target: "package", data: { relationship: "depends_on" } });
});

it("keeps a shared dependency independent rather than assigning an arbitrary owner", () => {
  const input = [node("one", "server"), node("two", "server"), node("package", "package")];
  const edges = ["one", "two"].map(source => ({ id: source, source, target: "package", data: { relationship: "depends_on" } }));
  const result = graphHierarchyLayout(input, edges);
  expect(result.nodes[2]!.data.semanticOwner).toBeUndefined();
  expect(result.nodes[2]!.position.x).toBeGreaterThan(result.nodes[0]!.position.x);
  expect(result.edges).toHaveLength(2);
});

it("keeps off-path package dependencies below their recorded owner in the selected-path model", () => {
  const { graph, selected } = branchingFixture();
  graph.nodes = graph.nodes.map(node => node.id === "pkg:urllib3" ? { ...node, semantic_layer: "package" } : node);
  const model = buildAttackPathGraphModel(graph, selected);
  expect(model.nodes.find(node => node.id === "pkg:urllib3")?.semanticOwner).toBe("server:filesystem");
  expect(model.nodes.find(node => node.id === "pkg:next")?.semanticOwner).toBeUndefined();
  graph.edges.push({ ...graph.edges.find(edge => edge.target === "pkg:urllib3")!, id: "shared-dependency", source: "server:github" });
  expect(buildAttackPathGraphModel(graph, selected).nodes.find(node => node.id === "pkg:urllib3")?.semanticOwner).toBeUndefined();
});

it("reserves compact rows for uniquely owned package context while keeping full cards clear", () => {
  const nodes = [node("server", "server"), node("package-a", "package"), node("package-b", "package")];
  const edges = nodes.slice(1).map(n => ({ id: n.id, source: "server", target: n.id, data: { relationship: "contains" } }));
  const result = semanticGraphLayout(nodes, edges, ["server"]);
  const children = result.nodes.slice(1);
  expect(children.every(child => child.style?.minHeight === 132)).toBe(true);
  expect(Math.abs(children[0]!.position.y - children[1]!.position.y)).toBe(156);
  expect(children.every(child => child.position.y >= 240)).toBe(true);
});

it("routes owner-to-subrow links around the same column through its outside ports", () => {
  const nodes = [node("server", "server"), node("package", "package")];
  const result = semanticGraphLayout(nodes, [{ id: "dependency", source: "server", target: "package", data: { relationship: "depends_on" } }], ["server"]);
  expect(result.edges[0]!.sourceHandle).toBeNull();
  expect(result.edges[0]!.targetHandle).toBe("context");
  expect(result.nodes[1]!.position.x).toBe(result.nodes[0]!.position.x);
});
