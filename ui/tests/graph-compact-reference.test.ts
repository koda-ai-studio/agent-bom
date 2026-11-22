import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { canvasName } from "@/components/graph-compact-node";

// The layout's input exactly as the investigation canvas hands it over for the reference correlation view.
const reference = JSON.parse(readFileSync("tests/fixtures/reference-layout-input.json", "utf8")) as { nodes: Node<LineageNodeData>[]; edges: Edge[]; selectedPath: string[] };
const { nodes, edges } = reference;

function curve(from: { x: number; y: number }, to: { x: number; y: number }, arc?: [number, number]) {
  const dx = to.x - from.x, c1 = { x: from.x + 0.45 * dx, y: from.y + (arc?.[0] ?? 0) }, c2 = { x: to.x - 0.45 * dx, y: arc ? from.y + arc[1] : to.y };
  return Array.from({ length: 65 }, (_, i) => {
    const t = i / 64, u = 1 - t;
    return { x: u ** 3 * from.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x + t ** 3 * to.x, y: u ** 3 * from.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t ** 3 * to.y };
  });
}

describe("reference correlation view placement", () => {
  const result = semanticGraphLayout(nodes, edges, reference.selectedPath);
  const at = (id: string) => result.nodes.find(node => node.id === id)!.position;

  it("puts the pinned manifest in the column right before its package, in a free row", () => {
    // Same column as the MCP server, the one right before the package.
    const centre = (id: string) => { const card = result.nodes.find(node => node.id === id)!; return card.position.x + Number(card.style!.width) / 2; };
    expect(centre("source:pinned-package")).toBe(centre("server:mcp:document-review"));
    expect(centre("server:mcp:document-review")).toBeLessThan(centre("package:mcp:pillow"));
    const peers = result.nodes.filter(node => node.id !== "source:pinned-package" && centre(node.id) === centre("source:pinned-package"));
    expect(peers.every(node => Math.abs(node.position.y - at("source:pinned-package").y) >= 150)).toBe(true);
  });

  it("draws every link as one curve, at most 2.5 times its straight distance, clear of every card but at most one quieter link", () => {
    // At most one link the caption model cannot prove clear is drawn quieter; the browser gate checks it never crosses text.
    expect(result.edges.filter(edge => edge.data?.passesBehind).length).toBeLessThanOrEqual(1);
    for (const edge of result.edges) {
      const points = curve(at(edge.source), at(edge.target), edge.data?.arcDy as [number, number] | undefined);
      const drawn = points.slice(1).reduce((sum, p, i) => sum + Math.hypot(p.x - points[i]!.x, p.y - points[i]!.y), 0);
      const chord = Math.hypot(at(edge.target).x - at(edge.source).x, at(edge.target).y - at(edge.source).y);
      expect(drawn / chord, edge.id).toBeLessThanOrEqual(2.5);
    }
  });

  it("keeps the whole view fittable at a legible zoom, widening name boxes only when every name then fits", () => {
    const xs = result.nodes.map(node => node.position.x + Number(node.style!.width) / 2), ys = result.nodes.map(node => node.position.y);
    const zoom = Math.min(1, (1320 * 0.9) / (Math.max(...xs) - Math.min(...xs) + 216), (590 * 0.9) / (Math.max(...ys) - Math.min(...ys) + 200));
    // Fit all never goes below its legible floor, so the layout must fit a 1440px canvas at or above it.
    expect(zoom).toBeGreaterThanOrEqual(0.4);
    const char = (14 * 0.88 * 0.55) / zoom;
    const widened = result.nodes.some(node => Number(node.style!.width) > 216 && !["package", "finding"].includes(String(node.data.semanticLayer)));
    if (widened) for (const node of result.nodes) for (const word of canvasName(node.data.label).split(" "))
      expect(word.length * char, `${node.id}: ${word}`).toBeLessThanOrEqual(Number(node.style!.width));
  });

  it("keeps the selected path on one straight row", () => {
    expect(new Set(reference.selectedPath.map(id => at(id).y))).toEqual(new Set([0]));
  });
});

describe("identifier captions", () => {
  const LAYERS: Record<string, string> = { server: "mcp_server", package: "package", vulnerability: "finding" };
  const make = (id: string, nodeType: string, label: string): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label, nodeType: nodeType as LineageNodeData["nodeType"], semanticLayer: LAYERS[nodeType] } });
  const graph = [make("server", "server", "filesystem"), make("pkg-a", "package", "filesystem-path-helpers"), make("pkg-b", "package", "left-pad"),
    make("cve-a", "vulnerability", "CVE-2026-123456"), make("cve-b", "vulnerability", "GHSA-abcd-efgh-ijkl")];
  const links: Edge[] = [["server", "pkg-a", "depends_on"], ["server", "pkg-b", "depends_on"], ["pkg-a", "cve-a", "vulnerable_to"], ["pkg-b", "cve-b", "vulnerable_to"]]
    .map(([source, target, relationship]) => ({ id: `${source}->${target}`, source: source!, target: target!, data: { relationship } }));
  const result = semanticGraphLayout(graph, links, ["server", "pkg-a", "cve-a"]);
  const card = (id: string) => result.nodes.find(node => node.id === id)!;
  const centre = (id: string) => card(id).position.x + Number(card(id).style!.width) / 2;

  it("widens package and finding boxes so a full id fits at the largest label size, keeping glyphs centred on their rank", () => {
    // 36-unit ceiling × 0.88 name scale × ~0.6 em per character.
    for (const id of ["pkg-a", "cve-a", "cve-b"]) expect(Number(card(id).style!.width), id).toBeGreaterThanOrEqual(card(id).data.label.length * 36 * 0.88 * 0.6);
    expect(Number(card("server").style!.width)).toBe(216);
    expect(centre("pkg-a")).toBe(centre("pkg-b"));
    expect(centre("cve-a")).toBe(centre("cve-b"));
    // Wide boxes in neighbouring ranks never overlap.
    expect(card("cve-a").position.x).toBeGreaterThanOrEqual(card("pkg-a").position.x + Number(card("pkg-a").style!.width));
  });

  it("levels each finding with its package even when the rank is shared", () => {
    expect(card("cve-a").position.y).toBe(card("pkg-a").position.y);
    expect(card("cve-b").position.y).toBe(card("pkg-b").position.y);
  });
});

describe("finding leaves in a shared rank", () => {
  const make = (id: string, nodeType: string, layer: string): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType: nodeType as LineageNodeData["nodeType"], semanticLayer: layer } });
  const graph = [make("server", "server", "mcp_server"), ...["a", "b", "c"].map(k => make(`pkg-${k}`, "package", "package")),
    ...["a1", "b1", "b2", "c1"].map(k => make(`cve-${k}`, "vulnerability", "finding"))];
  const pairs = [["server", "pkg-a", "depends_on"], ["server", "pkg-b", "depends_on"], ["server", "pkg-c", "depends_on"],
    ["pkg-a", "cve-a1", "vulnerable_to"], ["pkg-b", "cve-b1", "vulnerable_to"], ["pkg-b", "cve-b2", "vulnerable_to"], ["pkg-c", "cve-c1", "vulnerable_to"]];
  const links: Edge[] = pairs.map(([source, target, relationship]) => ({ id: `${source}->${target}`, source: source!, target: target!, data: { relationship } }));
  const result = semanticGraphLayout(graph, links);
  const y = (id: string) => result.nodes.find(node => node.id === id)!.position.y;

  it("puts the first finding of each package on the package's row and pushes its siblings apart", () => {
    expect(y("cve-a1")).toBe(y("pkg-a"));
    expect([y("cve-b1"), y("cve-b2")]).toContain(y("pkg-b"));
    expect(Math.abs(y("cve-b1") - y("cve-b2"))).toBeGreaterThanOrEqual(200);
    const order = ["cve-a1", "cve-b1", "cve-b2", "cve-c1"].map(y);
    expect([...order].sort((p, q) => p - q)).toEqual(order);
  });
});
