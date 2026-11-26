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
  it("does not wrap a foreign account asset even when its account node is absent from the loaded view", () => {
    const nodes = [node("acct", "account", "scope", { attributes: { account_id: "123456789012" } }),
      node("w", "container", "infra", { attributes: { account_id: "123456789012", internet_exposed: true } }),
      node("data", "dataStore", "asset", { attributes: { account_id: "210987654321" } })];
    const edges = [edge("acct", "w", "contains"), edge("w", "data", "can_access")];
    expect(enclosingEnvironment(nodes, edges)).toBeNull();
    const result = semanticGraphLayout(nodes, edges);
    expect(result.nodes.some(n => n.type === "boundaryFrame")).toBe(false);
    expect(result.edges.find(e => e.id === "w-data")).toMatchObject({ source: "w", target: "data", data: { relationship: "can_access" } });
  });
  it("never represents permission or cross-account trust as one containment context", () => {
    const { nodes, edges } = estate();
    expect(enclosingEnvironment(nodes, edges.map(link => link.source === "env" ? { ...link, data: { relationship: "can_access" } } : link))).toBeNull();
    expect(enclosingEnvironment(nodes, [...edges, edge("docs", "serving", "cross_account_trust")])).toBeNull();
  });
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
  it("colours the exposure path and retains direction markers for inspection", () => {
    const { nodes, edges } = estate();
    const out = semanticGraphLayout(nodes, edges);
    const path = out.edges.filter(e => e.data?.exposurePath === true).map(e => [e.source, e.target]);
    expect(path.sort()).toEqual([[INTERNET_ANCHOR_ID, "serving"], ["serving", "torch"], ["torch", "cve-crit"]].sort());
    for (const drawn of out.edges.filter(e => !e.hidden)) {
      expect(drawn.data?.restingVerb).toBeUndefined();
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

it("does not emphasize an explicitly non-traversable exposure link", () => {
  const nodes = [node(INTERNET_ANCHOR_ID, "cloudResource", "user"), node("w", "container", "infra"), node("finding", "vuln", "finding", { severity: "critical" })];
  const edges = [edge(INTERNET_ANCHOR_ID, "w", "exposed_to"), { ...edge("w", "finding", "vulnerable_to"), data: { relationship: "vulnerable_to", traversable: false } }];
  expect(exposureSpine(nodes, edges)).toEqual([INTERNET_ANCHOR_ID, "w"]);
});

it("does not promote a blocked parallel link when another edge carries the path", () => {
  const nodes = [node("a", "agent", "orchestration"), node("b", "server", "mcp_server")];
  const edges = [{ ...edge("a", "b", "uses"), data: { relationship: "uses", traversable: true } }, { ...edge("a", "b", "can_access"), id: "blocked", data: { relationship: "can_access", traversable: false } }];
  const result = semanticGraphLayout(nodes, edges, ["a", "b"]);
  expect(result.edges.find(e => e.id === "blocked")?.data?.pathEmphasis).toBe(false);
});

it("keeps the entry chain level, keeps findings beside their owners and identity-to-data below", () => {
  const nodes = [node("gateway", "cloudResource", "app", exposed), node("workload", "container", "infra"),
    node("finding", "vulnerability", "finding", { severity: "critical" }), node("role", "identity", "identity"), node("bucket", "dataStore", "asset")];
  const edges = [edge("gateway", "workload", "exposed_to"), edge("workload", "finding", "vulnerable_to"),
    edge("workload", "role", "authenticates_as"), edge("role", "bucket", "can_access")];
  const result = semanticGraphLayout(nodes, edges);
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  expect(at("gateway").y).toBe(at("workload").y);
  expect(at("finding").x).toBeGreaterThan(at("workload").x);
  expect(at("role").y).toBeGreaterThan(at("workload").y);
  expect(at("bucket").y).toBe(at("role").y);
  expect(at("bucket").x).toBeGreaterThan(at("role").x);
  expect(result.edges.map(e => [e.source, e.target])).toEqual(expect.arrayContaining(edges.map(e => [e.source, e.target])));
  const reordered = semanticGraphLayout([...nodes].reverse(), [...edges].reverse());
  for (const n of result.nodes) expect(reordered.nodes.find(other => other.id === n.id)?.position).toEqual(n.position);
});

it("uses available columns instead of stacking expanded findings into five rows", () => {
  const nodes = [node("gateway", "cloudResource", "app", exposed), node("workload", "container", "infra"),
    node("cluster", "cluster", "infra"), node("worker", "container", "infra"),
    node("critical", "vulnerability", "finding", { severity: "critical" }), node("worker-finding", "vulnerability", "finding"),
    node("gateway-finding", "misconfiguration", "finding"), node("role-finding", "misconfiguration", "finding"),
    node("role", "identity", "identity"), node("bucket", "dataStore", "asset")];
  const edges = [edge("gateway", "workload", "exposed_to"), edge("workload", "critical", "vulnerable_to"),
    edge("cluster", "workload", "hosts"), edge("cluster", "worker", "hosts"), edge("worker", "worker-finding", "vulnerable_to"),
    edge("gateway-finding", "gateway", "affects"), edge("role-finding", "role", "affects"),
    edge("workload", "role", "authenticates_as"), edge("role", "bucket", "can_access")];
  const result = semanticGraphLayout(nodes, edges);
  const shown = result.nodes.filter(n => !n.hidden);
  const ys = shown.map(n => n.position.y);
  expect(Math.max(...ys) - Math.min(...ys)).toBeLessThanOrEqual(520);
  const xs = shown.map(n => n.position.x);
  expect((Math.max(...xs) - Math.min(...xs)) / (Math.max(...ys) - Math.min(...ys))).toBeGreaterThanOrEqual(3.2);
  expect(new Set(shown.map(n => `${n.position.x}:${n.position.y}`)).size).toBe(shown.length);
  const row = (id: string) => result.nodes.find(node => node.id === id)!.position.y;
  expect(row("worker")).toBeLessThan(row("workload"));
  expect(row("worker-finding")).toBeLessThan(row("critical"));
  for (const edge of edges) expect(result.edges.find(e => e.id === edge.id)).toMatchObject({ source: edge.source, target: edge.target });
});

it("does not highlight a different traversable relationship beside the ranked witness", () => {
  const nodes = [node("a", "agent", "orchestration"), node("b", "server", "mcp_server")];
  const edges = [
    { ...edge("a", "b", "uses"), data: { relationship: "uses", traversable: true, rankedPathWitness: true } },
    { ...edge("a", "b", "contains"), id: "parallel", data: { relationship: "contains", traversable: true, rankedPathWitness: false } },
  ];
  const result = semanticGraphLayout(nodes, edges, ["a", "b"]);
  expect(result.edges.find(e => e.id === "parallel")?.data?.pathEmphasis).toBe(false);
  expect(result.edges.find(e => e.id !== "parallel")?.data?.pathEmphasis).toBe(true);
});

it("keeps an independent credential chain together instead of crossing the exposure spine", () => {
  const nodes = [node("serving", "container", "infra", exposed), node("pkg", "package", "package"),
    node("cve", "vuln", "finding", { severity: "critical" }), node("agent", "agent", "orchestration"),
    node("server", "server", "mcp_server"), node("credential", "credential", "identity"), node("data", "dataStore", "data")];
  const edges = [edge("serving", "pkg", "contains"), edge("pkg", "cve", "vulnerable_to"), edge("agent", "server", "uses"),
    edge("server", "credential", "exposes_cred"), edge("credential", "data", "can_access")];
  const result = semanticGraphLayout(nodes, edges);
  const point = (id: string) => result.nodes.find(node => node.id === id)!.position;
  const chain = ["agent", "server", "credential", "data"];
  expect(new Set(chain.map(id => point(id).y)).size).toBe(1);
  expect(point("agent").y).toBeGreaterThan(point("serving").y);
  for (let i = 1; i < chain.length; i++) expect(point(chain[i]!).x).toBeGreaterThan(point(chain[i - 1]!).x);
  expect(result.edges.filter(edge => !edge.data?.displayOnly).map(edge => [edge.id, edge.source, edge.target])).toEqual(edges.map(edge => [edge.id, edge.source, edge.target]));
  const reordered = semanticGraphLayout([...nodes].reverse(), [...edges].reverse());
  for (const node of result.nodes) expect(reordered.nodes.find(other => other.id === node.id)?.position).toEqual(node.position);
});

it("keeps sibling dependency chains level when their recorded scope is expanded", () => {
  const nodes = [node("scope", "environment", "scope", { connectedScope: true }),
    node("serving", "container", "infra", exposed), node("pkg", "package", "package"),
    node("cve", "vuln", "finding", { severity: "critical" }), node("agent", "agent", "orchestration"),
    node("server", "server", "mcp_server"), node("credential", "credential", "identity"), node("data", "dataStore", "data"),
    node("intake", "agent", "orchestration"), node("docs", "server", "mcp_server"), node("image", "package", "package"),
    node("image-cve", "vuln", "finding", { severity: "high" })];
  const edges = [edge("scope", "serving", "contains"), edge("scope", "agent", "contains"), edge("scope", "intake", "contains"),
    edge("serving", "pkg", "contains"), edge("pkg", "cve", "vulnerable_to"), edge("agent", "server", "uses"),
    edge("server", "credential", "exposes_cred"), edge("credential", "data", "can_access"),
    edge("intake", "docs", "uses"), edge("docs", "image", "depends_on"), edge("image", "image-cve", "vulnerable_to")];
  const result = semanticGraphLayout(nodes, edges);
  const point = (id: string) => result.nodes.find(node => node.id === id)!.position;
  const chains = [["serving", "pkg", "cve"], ["agent", "server", "credential", "data"], ["intake", "docs", "image", "image-cve"]];
  for (const chain of chains) {
    expect(new Set(chain.map(id => point(id).y)).size).toBe(1);
    for (let i = 1; i < chain.length; i++) expect(point(chain[i]!).x).toBeGreaterThan(point(chain[i - 1]!).x);
  }
  expect(new Set(chains.map(chain => point(chain[0]!).y)).size).toBe(3);
  expect(point("serving").y).toBeLessThan(point("agent").y);
  expect(point("serving").y).toBeLessThan(point("intake").y);
  expect(point("scope").x).toBeLessThan(point("agent").x);
  expect(result.nodes.find(node => node.type === "boundaryFrame")?.data.frameFor).toBe("scope");
  expect(result.edges.filter(edge => !edge.data?.displayOnly).map(edge => [edge.id, edge.source, edge.target])).toEqual(edges.map(edge => [edge.id, edge.source, edge.target]));
  const reordered = semanticGraphLayout([...nodes].reverse(), [...edges].reverse());
  for (const node of result.nodes) expect(reordered.nodes.find(other => other.id === node.id)?.position).toEqual(node.position);
});
