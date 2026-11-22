import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { COMPACT_RANK_GAP, COMPACT_ROW_GAP, packRank } from "@/lib/graph-compact-layout";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";

const LAYERS: Record<string, string> = { user: "user", container: "app", cloudResource: "infra", agent: "orchestration", server: "mcp_server",
  tool: "tool", role: "identity", credential: "identity", package: "package", vulnerability: "finding", account: "scope" };
const node = (id: string, nodeType: string, extra: Partial<LineageNodeData> = {}): Node<LineageNodeData> => ({
  id, position: { x: 0, y: 0 }, data: { label: id, nodeType: nodeType as LineageNodeData["nodeType"], semanticLayer: LAYERS[nodeType], ...extra },
});
const edge = (source: string, target: string, relationship = "uses"): Edge => ({ id: `${source}->${target}`, source, target, data: { relationship } });
const at = (result: { nodes: Node[] }, id: string) => result.nodes.find(n => n.id === id)!.position;

describe("compact attack-path layout", () => {
  it("draws the selected path as a straight horizontal spine over compressed columns", () => {
    const nodes = [node("person", "user"), node("agent", "agent"), node("server", "server"), node("cve", "vulnerability")];
    const edges = [edge("person", "agent"), edge("agent", "server"), edge("server", "cve", "vulnerable_to")];
    const result = semanticGraphLayout(nodes, edges, ["person", "agent", "server", "cve"]);
    expect(nodes.map(n => at(result, n.id).y)).toEqual([0, 0, 0, 0]);
    // Empty semantic columns between occupied ones are not drawn as gaps.
    expect(nodes.map(n => at(result, n.id).x)).toEqual([0, 1, 2, 3].map(i => i * COMPACT_RANK_GAP));
  });

  it("fans branches evenly above and below their parent", () => {
    const roles = ["a", "b", "c", "d", "e", "f"].map(id => node(id, "role"));
    const result = semanticGraphLayout([node("agent", "agent"), ...roles], roles.map(role => edge("agent", role.id, "can_access")));
    const ys = roles.map(role => at(result, role.id).y).sort((a, b) => a - b);
    const parent = at(result, "agent").y;
    expect((ys[0]! + ys.at(-1)!) / 2).toBeCloseTo(parent);
    ys.slice(1).forEach((y, i) => expect(y - ys[i]!).toBeGreaterThanOrEqual(COMPACT_ROW_GAP));
  });

  it("splits a spine node's siblings to both sides of the spine", () => {
    const nodes = [node("root", "agent"), node("left", "server"), node("right", "server")];
    const result = semanticGraphLayout(nodes, ["left", "right"].map(id => edge("root", id)), ["root"]);
    expect(at(result, "root").y).toBe(0);
    const ys = [at(result, "left").y, at(result, "right").y].sort((a, b) => a - b);
    expect(ys[0]).toBeLessThan(0);
    expect(ys[1]).toBeGreaterThan(0);
    expect(ys[0]).toBe(-ys[1]!);
  });

  it("puts a same-column contained child in its own rank just right of its parent", () => {
    const nodes = [node("cluster", "cloudResource"), node("pod", "cloudResource"), node("agent", "agent")];
    const result = semanticGraphLayout(nodes, [edge("cluster", "pod", "contains"), edge("pod", "agent", "runs")]);
    expect(at(result, "pod").x).toBe(at(result, "cluster").x + COMPACT_RANK_GAP);
    expect(at(result, "agent").x).toBe(at(result, "pod").x + COMPACT_RANK_GAP);
    expect(result.edges.every(e => e.sourceHandle == null && e.targetHandle == null)).toBe(true);
  });

  it("arcs a long link around a card that stands on its direct curve", () => {
    const nodes = [node("person", "user"), node("agent", "agent"), node("tool", "tool")];
    const result = semanticGraphLayout(nodes, [edge("person", "agent"), edge("agent", "tool"), edge("person", "tool", "invoked")], ["person", "agent", "tool"]);
    const long = result.edges.find(e => e.id === "person->tool")!;
    const arc = long.data?.arcDy as [number, number] | undefined;
    expect(arc).toHaveLength(2);
    expect(Math.max(...arc!.map(Math.abs))).toBeGreaterThan(0);
    expect(result.edges.find(e => e.id === "person->agent")!.data?.arcDy).toBeUndefined();
  });

  it("puts a package one rank right of its far-left owner and its finding one rank further", () => {
    const nodes = [node("api", "container"), node("tool", "tool"), node("pkg", "package"), node("cve", "vulnerability"), node("agent", "agent")];
    const result = semanticGraphLayout(nodes, [edge("api", "pkg", "contains"), edge("pkg", "cve", "vulnerable_to"), edge("api", "agent", "runs"), edge("agent", "tool")]);
    expect(at(result, "pkg").x).toBeGreaterThan(at(result, "api").x);
    expect(at(result, "pkg").x).toBeLessThan(at(result, "agent").x);
    expect(at(result, "cve").x).toBeGreaterThan(at(result, "pkg").x);
    expect(at(result, "cve").x).toBeLessThan(at(result, "tool").x);
  });

  it("draws a star's long links as single curves with no lane points", () => {
    const nodes = [node("account", "account"), node("bucket", "package"), node("cluster", "cloudResource"), node("gateway", "container")];
    const result = semanticGraphLayout(nodes, ["bucket", "cluster", "gateway"].map(id => edge("account", id, "contains")));
    expect(result.edges.every(link => link.type === "compact" && link.data?.lanePoints === undefined)).toBe(true);
  });

  it("never stacks two nodes of one rank closer than the row gap", () => {
    const servers = Array.from({ length: 5 }, (_, i) => node(`s${i}`, "server"));
    const agents = [node("a1", "agent"), node("a2", "agent")];
    const edges = [...servers.slice(0, 3).map(s => edge("a1", s.id)), ...servers.slice(2).map(s => edge("a2", s.id))];
    const result = semanticGraphLayout([...agents, ...servers], edges);
    const ranks = new Map<number, number[]>();
    for (const n of result.nodes) ranks.set(n.position.x, [...(ranks.get(n.position.x) ?? []), n.position.y]);
    for (const ys of ranks.values()) {
      ys.sort((a, b) => a - b).slice(1).forEach((y, i) => expect(y - ys[i]!).toBeGreaterThanOrEqual(COMPACT_ROW_GAP));
    }
  });

  it("places the internet anchor directly left of the exposed entry on its row", () => {
    const nodes = [node("api", "container", { attributes: { risk_context: { internet_exposed: true } } }), node("agent", "agent")];
    const result = semanticGraphLayout(nodes, [edge("api", "agent")], ["api", "agent"]);
    const anchor = at(result, INTERNET_ANCHOR_ID), api = at(result, "api");
    expect(anchor.y).toBe(0);
    expect(anchor.x).toBe(api.x - COMPACT_RANK_GAP);
    expect(Math.min(...result.nodes.map(n => n.position.x))).toBe(anchor.x);
  });

  it("draws every relationship with the compact edge and enters a reversed link from the far side", () => {
    const nodes = [node("agent", "agent"), node("server", "server")];
    const result = semanticGraphLayout(nodes, [edge("server", "agent", "serves")]);
    const drawn = result.edges[0]!;
    expect(drawn.type).toBe("compact");
    expect(drawn.sourceHandle).toBe("context");
    expect(drawn.targetHandle).toBe("context");
  });

  it("lays out a large map quickly and still keeps every rank's rows apart", () => {
    const kinds = ["user", "container", "cloudResource", "agent", "server", "tool", "package", "vulnerability"];
    const nodes = Array.from({ length: 600 }, (_, i) => node(`n${i}`, kinds[i % kinds.length]!));
    const edges = Array.from({ length: 1800 }, (_, i) => edge(`n${(i * 7) % 600}`, `n${(i * 13 + 5) % 600}`));
    const started = performance.now();
    const result = semanticGraphLayout(nodes, edges.filter(e => e.source !== e.target));
    expect(performance.now() - started).toBeLessThan(3000);
    const ranks = new Map<number, number[]>();
    for (const n of result.nodes) ranks.set(n.position.x, [...(ranks.get(n.position.x) ?? []), n.position.y]);
    for (const ys of ranks.values()) ys.sort((a, b) => a - b).slice(1).forEach((y, i) => expect(y - ys[i]!).toBeGreaterThanOrEqual(COMPACT_ROW_GAP - 1));
  });

  it("lays out a disconnected single-rank roll-up as a grid rather than a tower", () => {
    const accounts = Array.from({ length: 8 }, (_, i) => node(`acct${i}`, "account"));
    const result = semanticGraphLayout(accounts, []);
    expect(new Set(result.nodes.map(n => n.position.x)).size).toBeGreaterThan(1);
    expect(new Set(result.nodes.map(n => n.position.y)).size).toBeGreaterThan(1);
  });
});

it("places every node the same way whatever order the API returns nodes and links in", () => {
  const nodes = [node("a", "agent"), node("s1", "server"), node("s2", "server"), node("t", "tool"), node("p", "package"), node("u", "user")];
  const edges = [edge("u", "a"), edge("a", "s1"), edge("a", "s2"), edge("s1", "t"), edge("u", "p", "depends_on"), edge("a", "t")];
  const place = (n: typeof nodes, e: typeof edges) => Object.fromEntries(semanticGraphLayout(n, e).nodes.map(x => [x.id, x.position]));
  expect(place([...nodes].reverse(), [...edges].reverse())).toEqual(place(nodes, edges));
});

describe("rank packing", () => {
  it("keeps order, spacing and a symmetric fan around a shared target", () => {
    const ys = packRank([0, 0, 0].map((desired, i) => ({ id: String(i), desired })), COMPACT_ROW_GAP);
    expect([...ys.values()]).toEqual([-COMPACT_ROW_GAP, 0, COMPACT_ROW_GAP]);
  });

  it("anchors a spine item at zero and pushes the rest clear of it", () => {
    const ys = packRank([{ id: "up", desired: 10 }, { id: "spine", desired: 0, fixed: true }, { id: "down", desired: -5 }], 100);
    expect(ys.get("spine")).toBe(0);
    expect(ys.get("up")).toBeLessThanOrEqual(-100);
    expect(ys.get("down")).toBeGreaterThanOrEqual(100);
  });
});
