import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { readableGraphEdges } from "@/lib/graph-utils";
import { graphHierarchyLayout, orderHierarchyBranches } from "@/lib/graph-hierarchy-layout";
import { readableLineageDagreLr } from "@/lib/graph-node-dimensions";
import { graphConnectionPreview } from "@/lib/graph-connection-preview";
import { graphAdaptiveFrame } from "@/lib/graph-adaptive-frame";
import { COMPACT_NODE_WIDTH } from "@/lib/graph-compact-layout";
import { SEMANTIC_COLUMN_GAP, SEMANTIC_ROW_GAP } from "@/lib/graph-semantic-layout";

// Recorded semantic layers supplied by these API examples.
const layers: Record<string, string> = { agent: "orchestration", server: "mcp_server", container: "app", environment: "infra",
  sourceFile: "code", directory: "code", configFile: "code", ciJob: "ci", package: "package", vulnerability: "finding",
  misconfiguration: "finding", serviceAccount: "identity", role: "identity", tool: "tool", credential: "asset", dataStore: "asset", dataset: "asset", model: "orchestration" };
const node = (id: string, nodeType: LineageNodeData["nodeType"]): Node<LineageNodeData> => ({
  id, type: "containerNode", position: { x: 0, y: 0 }, data: { label: id, nodeType, semanticLayer: layers[nodeType] },
});
const edge = (id: string, source: string, target: string, relationship: string): Edge => ({
  id, source, target, data: { relationship, evidenceMode: "inferred" }, markerEnd: "arrow",
});

/** No two compact cards come closer than a row in one rank, or a rank across. */
function expectCompactCardsClear(nodes: Node[]) {
  for (const [i, a] of nodes.entries()) for (const b of nodes.slice(i + 1)) {
    expect(Math.abs(a.position.x - b.position.x) >= SEMANTIC_COLUMN_GAP || Math.abs(a.position.y - b.position.y) >= SEMANTIC_ROW_GAP).toBe(true);
  }
}

describe("evidence-driven graph flow", () => {
  it("reserves the semantic renderer footprint for a peer group", () => {
    const group = { ...node("peers", "server"), type: "clusterPillNode" };
    const result = graphHierarchyLayout([node("workspace", "agent"), group], [edge("uses", "workspace", "peers", "uses")]);
    expect(result.nodes.every(node => node.style?.width === COMPACT_NODE_WIDTH)).toBe(true);
    expect(result.nodes[1]!.position.x).toBeGreaterThan(result.nodes[0]!.position.x);
  });
  it("fits a compact three-source correlation without hiding its finding off canvas", () => {
    const sources = [node("file", "sourceFile"), node("image", "container"), node("deployment", "container")];
    const entries = [...sources, node("package", "package"), node("finding", "vulnerability")];
    const links = [...sources.map(n => edge(n.id, n.id, "package", "contains")), edge("finding", "package", "finding", "vulnerable_to")];
    const result = graphHierarchyLayout(entries, links, readableLineageDagreLr({ fitAspect: 1.65 }));
    const left = Math.min(...result.nodes.map(n => n.position.x));
    const top = Math.min(...result.nodes.map(n => n.position.y));
    const right = Math.max(...result.nodes.map(n => n.position.x + 240));
    const bottom = Math.max(...result.nodes.map(n => n.position.y + Number(n.style?.minHeight ?? 224)));
    expect(graphAdaptiveFrame({ bounds: { x: left, y: top, width: right - left, height: bottom - top }, width: 1134, availableHeight: 684, inspector: false }).fitAll).toBe(true);
  });

  it("orders a bounded multi-source workload by recorded semantic layers", () => {
    const entries = [node("service", "server"), node("deployment", "container"), node("image", "container"), node("file", "sourceFile"),
      node("workload", "agent"), node("package", "package"), node("identity", "serviceAccount"), node("tool", "tool"),
      node("finding", "vulnerability"), node("records", "dataStore")];
    entries[1]!.data.occurrenceRole = "deployment";
    const links = [edge("exposure", "service", "workload", "exposed_to"), edge("workload", "deployment", "workload", "contains"),
      ...["deployment", "image", "file"].map(id => edge(id, id, "package", "contains")),
      edge("identity", "workload", "identity", "authenticates_as"), edge("invocation", "workload", "tool", "invoked"),
      edge("permission", "identity", "records", "has_permission"), edge("finding", "package", "finding", "vulnerable_to")];
    const result = graphHierarchyLayout(entries, links, readableLineageDagreLr({ fitAspect: 1.65 }));
    const byId = new Map(result.nodes.map(n => [n.id, n.position]));
    expect(byId.get("deployment")!.x).toBeLessThan(byId.get("workload")!.x);
    expect(byId.get("workload")!.x).toBeLessThan(byId.get("service")!.x);
    expect(byId.get("service")!.x).toBeLessThan(byId.get("tool")!.x);
    expect(byId.get("tool")!.x).toBe(byId.get("identity")!.x);
    expect(byId.get("identity")!.x).toBeLessThan(byId.get("records")!.x);
    expect(result.edges.map(e => [e.id, e.source, e.target])).toEqual(links.map(e => [e.id, e.source, e.target]));
  });

  it("reserves overview caption space for a multi-source correlation", () => {
    const entries = [node("file", "sourceFile"), node("image", "container"), node("deployment", "container"), node("package", "package"), node("finding", "vulnerability")];
    entries[2]!.data.occurrenceRole = "deployment occurrence";
    const links = entries.slice(0, 3).map(n => edge(n.id, n.id, "package", "contains"));
    links.push(edge("finding", "package", "finding", "vulnerable_to"));
    const { nodes } = graphHierarchyLayout(entries, links, readableLineageDagreLr());
    expectCompactCardsClear(nodes);
  });

  it("reserves finding footer space in a compact branched AI environment", () => {
    const entries = [node("environment", "environment"), node("model", "container"), node("triage", "agent"), node("intake", "agent"), node("torch", "package"), node("tickets", "server"), node("documents", "server"), node("cve", "vulnerability"), node("credential", "credential"), node("pillow", "package")];
    const pairs = [["environment", "model"], ["environment", "triage"], ["environment", "intake"], ["model", "torch"], ["triage", "tickets"], ["intake", "documents"], ["torch", "cve"], ["tickets", "credential"], ["documents", "pillow"]];
    const links = pairs.map(([source, target]) => edge(`${source}-${target}`, source!, target!, "contains"));
    const result = graphHierarchyLayout(entries, links, readableLineageDagreLr({ fitAspect: 2.2 }));
    expectCompactCardsClear(result.nodes);
    expect(result.edges.map(e => [e.source, e.target])).toEqual(links.map(e => [e.source, e.target]));
  });

  it("reserves subtitle space for cross-vendor server and model branches", () => {
    const entries = [node("agent", "agent"), node("server", "server"), node("model", "model"), node("dataset", "dataset"), node("tool", "tool")];
    entries[1]!.data.description = "Warehouse connection";
    entries[2]!.data.description = "Model deployment";
    const links = ["server", "model", "dataset"].map(id => edge(id, "agent", id, "uses"));
    links.push(edge("tool", "server", "tool", "has_tool"));
    const { nodes } = graphHierarchyLayout(entries, links, readableLineageDagreLr());
    expectCompactCardsClear(nodes);
  });

  it("keeps aggregate member counts visible when overview relationship captions are quiet", () => {
    const entries = [node("package", "package"), { ...node("group", "vulnerability"), type: "clusterPillNode" }];
    const links = [{ ...edge("members", "package", "group", "vulnerable_to"), label: "22 members", data: { relationship: "vulnerable_to", isClusterEdge: true } }];
    const result = readableGraphEdges(graphHierarchyLayout(entries, links).edges);
    expect(result[0]!.label).toBe("22 members");
  });

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
      expect(displayed.data).toMatchObject(original.data);
    }
  });

  it("follows recorded engineering relationships and keeps warnings downstream of their subject", () => {
    const result = graphHierarchyLayout(nodes, edges);
    const x = new Map(result.nodes.map(n => [n.id, n.position.x]));
    // Contained items take the rank right of their container; a package and its CVE branch right of their owner.
    for (const id of ["source", "ci"]) expect(x.get(id)).toBeGreaterThan(x.get("repo")!);
    expect(x.get("source")).toBe(x.get("ci"));
    expect(x.get("app")).toBeLessThan(x.get("repo")!);
    expect(x.get("package")).toBeGreaterThan(x.get("app")!);
    expect(x.get("cve")).toBeGreaterThan(x.get("package")!);
    expect(x.get("warning")).toBeGreaterThan(x.get("ci")!);
    expect(result.edges.map(e => [e.id, e.source, e.target, e.data?.relationship, e.data?.evidenceMode, e.markerEnd]))
      .toEqual(edges.map(e => [e.id, e.source, e.target, e.data?.relationship, e.data?.evidenceMode, e.markerEnd]));
    // The warning reads downstream of its subject, so its recorded link is drawn back into it.
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

  it("bounds the initial repository view without changing its backend columns", () => {
    const folders = Array.from({ length: 40 }, (_, i) => node(`folder-${i}`, "directory"));
    const preview = graphConnectionPreview([node("repo", "directory"), ...folders], folders.map(n => edge(n.id, "repo", n.id, "contains")), "repo", 12)!;
    const result = graphHierarchyLayout(preview.nodes, preview.edges, readableLineageDagreLr());
    expect(preview.totalNodes).toBe(41);
    expect(preview.totalEdges).toBe(40);
    // The repository and the folders it contains share a layer: the folders take the next rank together.
    const folderXs = new Set(result.nodes.filter(n => n.id !== "repo").map(node => node.position.x));
    expect(folderXs.size).toBe(1);
    expect([...folderXs][0]).toBeGreaterThan(result.nodes.find(n => n.id === "repo")!.position.x);
    const ys = result.nodes.map(n => n.position.y);
    expect(Math.max(...ys) - Math.min(...ys)).toBeLessThan(4000);
    expect(result.edges).toHaveLength(11);
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

  it("keeps bounded overview captions quiet while retaining arrows and selectable meaning", () => {
    const result = graphHierarchyLayout(nodes, edges);
    const quiet = readableGraphEdges(result.edges);
    expect(quiet.find(e => e.id === "source")?.label).toBeUndefined();
    expect(result.edges.every(e => e.markerEnd === "arrow")).toBe(true);
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


it("does not turn correlation into a parent-child rank", () => {
  const entries = [node("left", "agent"), node("right", "agent")];
  const links = [edge("match", "left", "right", "possibly_correlates_with")];
  const result = graphHierarchyLayout(entries, links);
  expect(result.nodes[0]!.position.x).toBe(result.nodes[1]!.position.x);
  expect(result.edges[0]!.source).toBe("left");
  expect(result.edges[0]!.target).toBe("right");
});

it.each(["part_of", "hosted_on", "belongs_to"])("places the recorded parent first for %s without reversing the receipt", relationship => {
  const entries = [node("child", "agent"), node("parent", "container")];
  const link = edge("membership", "child", "parent", relationship);
  const result = graphHierarchyLayout(entries, [link]);
  expect(result.nodes.find(n => n.id === "parent")!.position.x).toBeLessThan(result.nodes.find(n => n.id === "child")!.position.x);
  expect(result.edges[0]).toMatchObject({ source: "child", target: "parent", data: { relationship }, markerEnd: "arrow" });
});


it("keeps dense graphs quiet without dropping relationships", () => {
  const nodes = Array.from({ length: 30 }, (_, i) => node(String(i), "agent"));
  const edges = nodes.slice(1).map(n => edge(n.id, "0", n.id, "uses"));
  const result = graphHierarchyLayout(nodes, edges);
  expect(result.edges).toHaveLength(edges.length);
  expect(result.edges.every(e => e.data?.quietLabel)).toBe(true);
});
