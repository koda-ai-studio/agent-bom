import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";
import { enclosingEnvironment, exposureSpine } from "@/lib/graph-exposure-spine";
import { SEMANTIC_COLUMN_GAP, SEMANTIC_ROW_GAP, semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { separateCards } from "@/lib/graph-card-separation";
import { COMPACT_ROW_GAP } from "@/lib/graph-compact-layout";

const node = (id: string, nodeType: string, layer: string, extra: Partial<LineageNodeData> = {}): Node<LineageNodeData> =>
  ({ id, type: `${nodeType}Node`, position: { x: 0, y: 0 }, data: { label: id, nodeType, semanticLayer: layer, attributes: {}, ...extra } as LineageNodeData });
const edge = (source: string, target: string, relationship: string): Edge => ({ id: `${source}-${target}`, source, target, data: { relationship } });
const exposed = { attributes: { internet_exposed: true } };

/** The README sample: one exposed workload and two agent chains, all inside one environment. */
function estate() {
  const nodes = [node("env", "environment", "scope"), node("serving", "container", "infra", exposed), node("torch", "package", "package"),
    node("cve-crit", "vuln", "finding", { severity: "critical" }), node("intake", "agent", "orchestration"), node("docs", "server", "mcp_server"),
    node("pillow", "package", "package"), node("cve-high", "vuln", "finding", { severity: "high" })];
  const edges = [edge("env", "serving", "contains"), edge("env", "intake", "contains"), edge("serving", "torch", "contains"),
    edge("torch", "cve-crit", "vulnerable_to"), edge("intake", "docs", "uses"), edge("docs", "pillow", "depends_on"), edge("pillow", "cve-high", "vulnerable_to")];
  return { nodes, edges };
}

describe("exposure spine", () => {
  const anchor = node(INTERNET_ANCHOR_ID, "cloudResource", "user");
  it("walks recorded links from the Internet to the most severe reachable finding", () => {
    const nodes = [anchor, node("w", "container", "infra"), node("a", "package", "package"), node("b", "package", "package"),
      node("low", "vuln", "finding", { severity: "low" }), node("crit", "vuln", "finding", { severity: "critical" })];
    const edges = [edge(INTERNET_ANCHOR_ID, "w", "exposed_to"), edge("w", "a", "contains"), edge("a", "low", "vulnerable_to"),
      edge("w", "b", "contains"), edge("b", "crit", "vulnerable_to")];
    expect(exposureSpine(nodes, edges)).toEqual([INTERNET_ANCHOR_ID, "w", "b", "crit"]);
  });
  it("never walks a link backwards or invents a hop", () => {
    const nodes = [anchor, node("w", "container", "infra"), node("crit", "vuln", "finding", { severity: "critical" })];
    expect(exposureSpine(nodes, [edge(INTERNET_ANCHOR_ID, "w", "exposed_to"), edge("crit", "w", "affects")])).toEqual([INTERNET_ANCHOR_ID, "w"]);
    expect(exposureSpine(nodes.slice(1), [edge("w", "crit", "vulnerable_to")])).toEqual([]);
  });
});

describe("environment boundary", () => {
  it("frames an environment only when it is the single root holding every other node", () => {
    const { nodes, edges } = estate();
    expect(enclosingEnvironment(nodes, edges)?.id).toBe("env");
    expect(enclosingEnvironment([...nodes, node("stray", "agent", "orchestration")], edges)).toBeNull();
    expect(enclosingEnvironment(nodes, [...edges, edge("intake", "env", "part_of")])).toBeNull();
  });

  it("draws the frame around the cards with the Internet outside it, on the exposed asset's row", () => {
    const { nodes, edges } = estate();
    const out = semanticGraphLayout(nodes, edges);
    const frame = out.nodes.find(n => n.type === "boundaryFrame")!;
    const internet = out.nodes.find(n => n.id === INTERNET_ANCHOR_ID)!;
    const serving = out.nodes.find(n => n.id === "serving")!;
    expect(out.nodes.find(n => n.id === "env")!.hidden).toBe(true);
    expect(frame.data.frameLinks).toBe(2);
    expect(internet.position.x).toBeLessThan(frame.position.x);
    expect(internet.position.y).toBe(serving.position.y);
    for (const card of out.nodes.filter(n => !n.hidden && n.type !== "boundaryFrame" && n.id !== INTERNET_ANCHOR_ID)) {
      expect(card.position.x).toBeGreaterThanOrEqual(frame.position.x);
      expect(card.position.y).toBeGreaterThanOrEqual(frame.position.y);
      expect(card.position.x).toBeLessThan(frame.position.x + Number(frame.style!.width));
      expect(card.position.y).toBeLessThan(frame.position.y + Number(frame.style!.height));
    }
  });

  it("is stable when a layout runs again over its own output", () => {
    const { nodes, edges } = estate();
    const once = semanticGraphLayout(nodes, edges);
    const twice = semanticGraphLayout(once.nodes, once.edges);
    expect(twice.nodes.filter(n => n.type === "boundaryFrame")).toHaveLength(1);
    expect(twice.nodes.map(n => [n.id, n.position, n.hidden ?? false])).toEqual(once.nodes.map(n => [n.id, n.position, n.hidden ?? false]));
  });

  it("is not a card the separation pass keeps clear of", () => {
    const { nodes, edges } = estate();
    const out = semanticGraphLayout(nodes, edges).nodes.map(n => ({ ...n, measured: { width: n.type === "boundaryFrame" ? 2000 : 200, height: n.type === "boundaryFrame" ? 900 : 120 } }));
    expect(separateCards(out).map(n => n.position)).toEqual(out.map(n => n.position));
  });
});

describe("small map reading", () => {
  it("colours the exposure path, names every link and shows each one's direction", () => {
    const { nodes, edges } = estate();
    const out = semanticGraphLayout(nodes, edges);
    const path = out.edges.filter(e => e.data?.exposurePath === true).map(e => [e.source, e.target]);
    expect(path.sort()).toEqual([[INTERNET_ANCHOR_ID, "serving"], ["serving", "torch"], ["torch", "cve-crit"]].sort());
    for (const drawn of out.edges.filter(e => !e.hidden)) {
      expect(drawn.data?.restingVerb).toBe(true);
      expect(drawn.markerEnd).toBeTruthy();
    }
  });

  it("starts the first branch one row under the spine", () => {
    const { nodes, edges } = estate();
    const out = semanticGraphLayout(nodes, edges);
    const spineRow = out.nodes.find(n => n.id === "serving")!.position.y;
    expect(out.nodes.find(n => n.id === "intake")!.position.y - spineRow).toBe(COMPACT_ROW_GAP);
  });

  it("keeps the scope as a card on a map without the Internet", () => {
    const nodes = [node("env", "environment", "scope"), node("w", "container", "infra"), node("cve", "vuln", "finding", { severity: "high" })];
    const out = semanticGraphLayout(nodes, [edge("env", "w", "contains"), edge("w", "cve", "vulnerable_to")]);
    expect(out.nodes.some(n => n.type === "boundaryFrame")).toBe(false);
    expect(out.nodes.find(n => n.id === "env")!.hidden).toBeFalsy();
  });

  it("frames a cloud account like an environment", () => {
    const nodes = [node("acct", "account", "scope"), node("w", "container", "infra", exposed), node("cve", "vuln", "finding", { severity: "high" })];
    const out = semanticGraphLayout(nodes, [edge("acct", "w", "contains"), edge("w", "cve", "vulnerable_to")]);
    expect(out.nodes.find(n => n.type === "boundaryFrame")?.data.frameFor).toBe("acct");
  });

  it("puts the Internet in the free slot just before the asset it reaches, and keeps verbs off steep links", () => {
    const nodes = [node("cfg", "configFile", "code"), node("w", "container", "infra", exposed),
      node("pkg", "package", "package"), node("cve", "vuln", "finding", { severity: "critical" })];
    const edges = [edge("cfg", "w", "configures"), edge("w", "pkg", "contains"), edge("pkg", "cve", "vulnerable_to")];
    const out = semanticGraphLayout(nodes, edges);
    const at = (id: string) => out.nodes.find(n => n.id === id)!.position;
    // A short arrow: the Internet ends at most one column left of the asset and at most a row away.
    expect(at("w").x - at(INTERNET_ANCHOR_ID).x).toBeGreaterThan(0);
    expect(at("w").x - at(INTERNET_ANCHOR_ID).x).toBeLessThanOrEqual(SEMANTIC_COLUMN_GAP);
    expect(Math.abs(at("w").y - at(INTERNET_ANCHOR_ID).y)).toBeLessThanOrEqual(SEMANTIC_ROW_GAP);
    for (const drawn of out.edges.filter(e => !e.hidden)) {
      const a = at(drawn.source), b = at(drawn.target);
      if (Math.abs(b.y - a.y) > Math.abs(b.x - a.x)) expect(drawn.data?.restingVerb).toBeUndefined();
    }
  });
});
