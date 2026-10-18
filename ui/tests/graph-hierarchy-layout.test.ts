import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { readableGraphEdges } from "@/lib/graph-utils";
import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
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
