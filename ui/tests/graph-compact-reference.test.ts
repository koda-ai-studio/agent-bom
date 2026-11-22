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
    // Finding links never cross: the findings read in the same order as their packages.
    const owner: Record<string, string> = { "cve-a1": "pkg-a", "cve-b1": "pkg-b", "cve-b2": "pkg-b", "cve-c1": "pkg-c" };
    const byY = Object.keys(owner).sort((p, q) => y(p) - y(q)).map(id => y(owner[id]!));
    expect([...byY].sort((p, q) => p - q)).toEqual(byY);
  });
});

describe("layout reuse", () => {
  it("reuses the placement for a graph whose structure is unchanged, so re-renders stay fast", () => {
    const first = performance.now();
    const a = semanticGraphLayout(nodes, edges, reference.selectedPath);
    const cold = performance.now() - first;
    // Same structure, new objects with a presentation-only change (a highlight).
    const again = nodes.map(node => ({ ...node, data: { ...node.data, highlighted: !node.data.highlighted } }));
    const start = performance.now();
    const b = semanticGraphLayout(again, edges.map(edge => ({ ...edge })), reference.selectedPath);
    const warm = performance.now() - start;
    expect(b.nodes.map(node => node.position)).toEqual(a.nodes.map(node => node.position));
    expect(b.nodes.find(node => node.id === nodes[0]!.id)!.data.highlighted).toBe(true);
    expect(warm).toBeLessThan(Math.max(5, cold / 4));
  });
});

describe("reference correlation with the side navigation open", () => {
  it("keeps the tool between the service account and pillow and clears every card box at the nav-open canvas", async () => {
    const { setLayoutFrame } = await import("@/lib/graph-compact-arcs");
    setLayoutFrame(1135, 552);
    try {
      const result = semanticGraphLayout(nodes, edges, reference.selectedPath);
      const y = (id: string) => result.nodes.find(node => node.id === id)!.position.y;
      const [sa, tool, pillow] = [y("identity:model:reference-workload"), y("tool:runtime:render-untrusted-image"), y("package:mcp:pillow")];
      expect((sa < tool && tool < pillow) || (sa > tool && tool > pillow)).toBe(true);
      // Only the manifest's link into its package's left side may be drawn quieter; the browser gate checks it clears text.
      expect(result.edges.filter(edge => edge.data?.passesBehind && edge.source !== "source:pinned-package").map(edge => edge.id)).toEqual([]);
    } finally { setLayoutFrame(0, 0); }
  });
});

describe("the /graph route with the side navigation open", () => {
  it("leaves room under a name that breaks onto two lines at its hyphens, so no card is pushed out of its row", async () => {
    const { setLayoutFrame } = await import("@/lib/graph-compact-arcs");
    const nav = JSON.parse(readFileSync("tests/fixtures/reference-nav-layout-input.json", "utf8")) as { nodes: Node<LineageNodeData>[]; edges: Edge[]; selectedPath: string[] };
    setLayoutFrame(1134, 551);
    try {
      const result = semanticGraphLayout(nav.nodes, nav.edges, nav.selectedPath);
      const at = (id: string) => result.nodes.find(node => node.id === id)!.position;
      // "reference-evidence-workload" wraps after a hyphen at this zoom: the card under it needs a tall card's room.
      const sa = at("identity:model:reference-workload"), tool = at("tool:runtime:render-untrusted-image");
      if (Math.abs(sa.x - tool.x) < 1 && tool.y > sa.y) expect(tool.y - sa.y).toBeGreaterThanOrEqual(236);
      const [s, t, p] = [sa.y, tool.y, at("package:mcp:pillow").y];
      expect((s < t && t < p) || (s > t && t > p)).toBe(true);
    } finally { setLayoutFrame(0, 0); }
  });
});

describe("room under names that take more than two lines", () => {
  it("leaves every card's whole name clear of the next card in its rank, at the zoom Fit all picks", async () => {
    const { setLayoutFrame, captionExtent, fitZoom } = await import("@/lib/graph-compact-arcs");
    const nav = JSON.parse(readFileSync("tests/fixtures/reference-nav-layout-input.json", "utf8")) as { nodes: Node<LineageNodeData>[]; edges: Edge[]; selectedPath: string[] };
    setLayoutFrame(1134, 551);
    try {
      const result = semanticGraphLayout(nav.nodes, nav.edges, nav.selectedPath);
      const centre = (node: Node<LineageNodeData>) => ({ x: node.position.x + Number(node.style!.width) / 2, y: node.position.y });
      const zoom = fitZoom(new Map(result.nodes.map(node => [node.id, centre(node)])), 216);
      let stacked = 0, multiLine = 0;
      for (const upper of result.nodes) for (const lower of result.nodes) {
        if (centre(upper).x !== centre(lower).x || lower.position.y <= upper.position.y) continue;
        const caption = captionExtent({ name: canvasName(String(upper.data.label)), typeLine: "Type", box: Number(upper.style!.width) }, 216, zoom);
        stacked++;
        if (caption.nameLines.length > 2) multiLine++;
        // The lower card's glyph top sits its glyph radius above its row.
        expect(lower.position.y - upper.position.y, `${upper.id} over ${lower.id}`).toBeGreaterThanOrEqual(caption.depth + caption.above);
      }
      // The fixture stacks cards in a rank, and at least one of them has a name longer than two lines.
      expect(stacked).toBeGreaterThan(0);
      expect(multiLine).toBeGreaterThan(0);
    } finally { setLayoutFrame(0, 0); }
  });
});
