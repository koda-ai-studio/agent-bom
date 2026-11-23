import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { foldPackageEvidence, seenInSummary } from "@/lib/graph-evidence-fold";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { graphInvestigationContext, selectInvestigationContext } from "@/lib/graph-investigation-context";

const reference = JSON.parse(readFileSync("tests/fixtures/reference-layout-input.json", "utf8")) as { nodes: Node<LineageNodeData>[]; edges: Edge[]; selectedPath: string[] };

describe("folding dependency evidence into the package on a correlation overview", () => {
  const folded = foldPackageEvidence(reference.nodes, reference.edges);

  it("folds the image inventory and the pinned manifest into pillow, naming each source and the workload that runs the image", () => {
    const ids = folded.nodes.map(node => node.id);
    expect(ids).not.toContain("container:sbom:reference-api");
    expect(ids).not.toContain("source:pinned-package");
    const pillow = folded.nodes.find(node => node.id === "package:mcp:pillow")!;
    expect(pillow.data.seenIn?.map(entry => `${entry.id}:${entry.role}`).sort()).toEqual(["container:sbom:reference-api:image inventory", "source:pinned-package:manifest"]);
    const summary = seenInSummary(pillow.data.seenIn!);
    expect(summary).toMatch(/^Seen in 2 sources: /);
    expect(summary).toContain("image inventory, run by");
    expect(summary).toContain("manifest");
    // Only the folded cards' links leave; every other relationship is still drawn.
    expect(folded.edges.length).toBe(reference.edges.length - 3);
    expect(folded.edges.some(edge => edge.source === "package:mcp:pillow" && edge.target === "vulnerability:sbom:cve-2023-4863")).toBe(true);
  });

  it("lays the folded overview out with no two links crossing", () => {
    const result = semanticGraphLayout(folded.nodes, folded.edges, reference.selectedPath);
    const at = new Map(result.nodes.map(node => [node.id, { x: node.position.x + Number(node.style!.width) / 2, y: node.position.y }]));
    const side = (p: { x: number; y: number }, q: { x: number; y: number }, r: { x: number; y: number }) => Math.sign((q.x - p.x) * (r.y - p.y) - (q.y - p.y) * (r.x - p.x));
    let crossings = 0;
    result.edges.forEach((a, i) => result.edges.slice(i + 1).forEach(b => {
      if (new Set([a.source, a.target, b.source, b.target]).size < 4) return;
      const [p, q, r, t] = [at.get(a.source)!, at.get(a.target)!, at.get(b.source)!, at.get(b.target)!];
      if (side(p, q, r) * side(p, q, t) < 0 && side(r, t, p) * side(r, t, q) < 0) crossings++;
    }));
    expect(crossings).toBe(0);
    expect(result.edges.filter(edge => edge.data?.passesBehind)).toEqual([]);
  });

  it("keeps a source that records more than one package, links elsewhere, or is a package's only link", () => {
    const node = (id: string, nodeType: string): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType: nodeType as LineageNodeData["nodeType"] } });
    const link = (source: string, target: string, relationship: string): Edge => ({ id: `${source}-${target}`, source, target, data: { relationship } });
    const nodes = [node("lock", "sourceFile"), node("a", "package"), node("b", "package"), node("only", "sourceFile"), node("lonely", "package"), node("server", "server")];
    const edges = [link("lock", "a", "depends_on"), link("lock", "b", "depends_on"), link("server", "a", "depends_on"), link("only", "lonely", "depends_on")];
    expect(foldPackageEvidence(nodes, edges).folded).toBe(0);
  });

  it("folds only on a desktop canvas's whole view; a phone's chain list and the dependency view keep every source", () => {
    const context = graphInvestigationContext(reference.nodes, reference.edges, { correlation: true })!;
    expect(selectInvestigationContext(context, "all", { foldEvidence: true }).nodes).toHaveLength(reference.nodes.length - 2);
    expect(selectInvestigationContext(context, "all").nodes).toHaveLength(reference.nodes.length);
    expect(selectInvestigationContext(context, "dependency", { foldEvidence: true }).nodes.map(node => node.id)).toEqual(expect.arrayContaining(["container:sbom:reference-api", "source:pinned-package"]));
  });
});
