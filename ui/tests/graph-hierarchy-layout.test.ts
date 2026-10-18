import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { readableGraphEdges } from "@/lib/graph-utils";
import { graphHierarchyLayout, orderHierarchyBranches } from "@/lib/graph-hierarchy-layout";
import { readableLineageDagreLr } from "@/lib/graph-node-dimensions";

const node = (id: string, nodeType: LineageNodeData["nodeType"]): Node<LineageNodeData> => ({
  id, type: "containerNode", position: { x: 0, y: 0 }, data: { label: id, nodeType },
});
const edge = (id: string, source: string, target: string, relationship: string): Edge => ({
  id, source, target, data: { relationship, evidenceMode: "inferred" }, markerEnd: "arrow",
});

describe("evidence-driven graph flow", () => {
  const nodes = [node("repo", "directory"), node("source", "sourceFile"), node("ci", "ciJob"),
    node("app", "container"), node("package", "package"), node("cve", "vulnerability"), node("warning", "misconfiguration")];
  const edges = [edge("source", "repo", "source", "contains"), edge("build", "repo", "ci", "contains"),
    edge("config", "ci", "app", "configures"), edge("import", "source", "package", "imports"),
    edge("dependency", "app", "package", "contains"), edge("vuln", "package", "cve", "vulnerable_to"),
    edge("warning", "warning", "ci", "affects")];

  it("keeps the existing node renderer, icons, colors and metadata unchanged", () => {
    const result = graphHierarchyLayout(nodes, edges);
    for (const original of nodes) {
      const displayed = result.nodes.find(n => n.id === original.id)!;
      expect(displayed.type).toBe(original.type);
      expect(displayed.data).toEqual(original.data);
    }
  });

  it("follows recorded engineering relationships and keeps warnings downstream of their subject", () => {
    const result = graphHierarchyLayout(nodes, edges);
    const x = new Map(result.nodes.map(n => [n.id, n.position.x]));
    for (const [from, to] of [["repo", "source"], ["repo", "ci"], ["ci", "app"], ["app", "package"], ["package", "cve"], ["ci", "warning"]]) {
      expect(x.get(from!)).toBeLessThan(x.get(to!)!);
    }
    expect(result.edges.map(e => [e.id, e.source, e.target, e.data?.relationship, e.data?.evidenceMode, e.markerEnd]))
      .toEqual(edges.map(e => [e.id, e.source, e.target, e.data?.relationship, e.data?.evidenceMode, e.markerEnd]));
    expect(result.edges.find(e => e.id === "warning")?.sourceHandle).toBe("context");
  });

  it("retains every shared-finding relationship without inventing an owner", () => {
    const links = [...edges, edge("shared", "warning", "app", "affects")];
    const result = graphHierarchyLayout(nodes, links);
    expect(result.nodes).toHaveLength(nodes.length);
    expect(result.edges.map(e => [e.id, e.source, e.target])).toEqual(links.map(e => [e.id, e.source, e.target]));
  });

  it("is deterministic under reordered provider responses", () => {
    const positions = (result: ReturnType<typeof graphHierarchyLayout>) => Object.fromEntries(result.nodes.map(n => [n.id, n.position]));
    expect(positions(graphHierarchyLayout(nodes, edges))).toEqual(positions(graphHierarchyLayout([...nodes].reverse(), [...edges].reverse())));
  });

  it("keeps an expanded repository fan-out wrapped instead of making a tall stack", () => {
    const folders = Array.from({ length: 40 }, (_, i) => node(`folder-${i}`, "directory"));
    const result = graphHierarchyLayout([node("repo", "directory"), ...folders], folders.map(n => edge(n.id, "repo", n.id, "contains")), readableLineageDagreLr());
    const ys = result.nodes.map(n => n.position.y);
    expect(Math.max(...ys) - Math.min(...ys)).toBeLessThan(4000);
    expect(result.edges).toHaveLength(40);
  });

  it("aligns sibling folders even when one branch has a deeper build pipeline", () => {
    const entries = [node("repo", "directory"), node("src", "directory"), node("deploy", "directory"), node("workflow", "configFile"), node("build", "ciJob"), node("app", "container")];
    const links = [edge("src", "repo", "src", "contains"), edge("deploy", "repo", "deploy", "contains"), edge("workflow", "src", "workflow", "contains"), edge("build", "workflow", "build", "configures"), edge("app", "build", "app", "configures"), edge("deploy-app", "deploy", "app", "configures")];
    const result = graphHierarchyLayout(entries, links);
    expect(result.nodes.find(n => n.id === "src")!.position.x).toBe(result.nodes.find(n => n.id === "deploy")!.position.x);
    expect(result.edges.map(e => [e.source, e.target])).toEqual(links.map(e => [e.source, e.target]));
  });

  it("retains cyclic relationships without inventing a hierarchy root", () => {
    const entries = [node("a", "server"), node("b", "server")];
    const links = [edge("ab", "a", "b", "uses"), edge("ba", "b", "a", "uses")];
    const result = graphHierarchyLayout(entries, links);
    expect(result.edges).toHaveLength(2);
    expect(result.nodes.every(n => Number.isFinite(n.position.x) && Number.isFinite(n.position.y))).toBe(true);
  });

  it("keeps overview connections quiet and reveals relationship labels on selection", () => {
    const result = graphHierarchyLayout(nodes, edges);
    const quiet = readableGraphEdges(result.edges);
    expect(quiet.find(e => e.id === "source")?.label).toBeUndefined();
    expect(quiet.find(e => e.id === "config")?.label).toBeUndefined();
    const selected = readableGraphEdges(result.edges, new Set(["repo", "source"]));
    expect(selected.find(e => e.id === "source")?.label).toBeDefined();
    expect(quiet.find(e => e.id === "source")?.ariaLabel).toContain("relationship");
  });
});

it("groups converging branches across layers without interleaving the independent source path", () => {
  const positions: Record<string, [number, number]> = {
    repo: [0, 1], workflowDir: [1, 0], srcDir: [1, 1], deployDir: [1, 2],
    workflow: [2, 0], source: [2, 1], config: [2, 2], build: [3, 0.5], dependency: [3, 1.5],
    warning: [4, 0], app: [4, 1], cve: [4, 2],
  };
  const entries = Object.entries(positions).map(([id, [x, y]]) => ({ ...node(id, "directory"), position: { x: x * 400, y: y * 350 } }));
  const links = [["repo", "workflowDir"], ["repo", "srcDir"], ["repo", "deployDir"], ["workflowDir", "workflow"],
    ["srcDir", "source"], ["deployDir", "config"], ["workflow", "build"], ["source", "dependency"],
    ["build", "warning"], ["build", "app"], ["config", "app"], ["dependency", "cve"]]
    .map(([source, target]) => edge(`${source}-${target}`, source!, target!, "contains"));
  const ordered = orderHierarchyBranches(entries, links);
  const y = (id: string) => ordered.find(n => n.id === id)!.position.y;
  expect(y("source") < Math.min(y("workflow"), y("config")) || y("source") > Math.max(y("workflow"), y("config"))).toBe(true);
});
