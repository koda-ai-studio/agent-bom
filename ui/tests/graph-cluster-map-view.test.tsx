import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { ClusterMapNode, ClusterMapResponse } from "@/lib/graph-cluster-map";

const { getGraphClusterMap, searchGraph } = vi.hoisted(() => ({ getGraphClusterMap: vi.fn(), searchGraph: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { getGraphClusterMap, searchGraph } }));

import { GraphClusterMap } from "@/components/graph-cluster-map";

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
beforeEach(() => { getGraphClusterMap.mockReset(); searchGraph.mockReset(); });
afterEach(() => vi.clearAllMocks());

const group = (key: string, tier: number, count: number, extra: Partial<ClusterMapNode> = {}): ClusterMapNode => ({
  id: `@group:${key}`, kind: "cluster", cluster_key: key, label: key, tier, member_count: count, worst_severity: "none", risky: false, expanded: false, on_attack_path_count: 0, ...extra,
});

function frame(params: URLSearchParams): ClusterMapResponse {
  const expanded = params.getAll("expand");
  const focus = params.get("focus");
  const npmOpen = expanded.includes("@group:package:npm") || focus === "pkg:9";
  const offset = Number(params.getAll("page").find(item => item.endsWith("@group:package:npm"))?.split(":")[0] ?? 0);
  const nodes: ClusterMapNode[] = [
    group("type:agent", 1, 2, { risky: true, on_attack_path_count: 1, worst_severity: "critical" }),
    group("type:server", 2, 3),
    group("package:npm", 3, 10, { risky: true, worst_severity: "critical", expanded: npmOpen, shown_member_count: npmOpen ? 2 : 0 }),
  ];
  if (npmOpen) {
    const ids = focus ? ["pkg:9"] : [`pkg:${offset + 1}`, `pkg:${offset + 2}`];
    for (const id of ids) nodes.push({ id, kind: "member", cluster_id: "@group:package:npm", label: id, tier: 3, severity: "none", entity_type: "package", focused: id === focus });
    nodes.push({ id: "@more:package:npm", kind: "more", cluster_id: "@group:package:npm", label: `+${10 - ids.length} more`, tier: 3, count: 10 - ids.length, offset, limit: 2, next_offset: offset + 2, prev_offset: offset ? offset - 2 : null });
  }
  if (params.get("risky_only") !== "true") nodes.push(group("type:credential", 5, 1));
  return {
    scan_id: "s1", tenant_id: "default", mode: "cluster_map", tiers: [], nodes, clusters: [], filters: { risky_only: params.get("risky_only") === "true", member_limit: 2 },
    edges: [
      { id: "a->s", source: "@group:type:agent", target: "@group:type:server", count: 3, risky: false, relationships: [{ relationship: "uses", count: 3 }] },
      { id: "s->n", source: "@group:type:server", target: npmOpen ? "@more:package:npm" : "@group:package:npm", count: npmOpen ? 8 : 10, risky: false, relationships: [{ relationship: "depends_on", count: npmOpen ? 8 : 10 }] },
    ],
    focus: focus ? { node_id: focus, cluster_id: "@group:package:npm", found: true } : null,
    summary: { total_nodes: 16, total_edges: 13, cluster_count: 4, listed_cluster_count: 4, visible_cluster_count: 4, folded_cluster_count: 0, filtered_node_count: 0, filtered_edge_count: 0, internal_edge_count: 0,
      drawn_bundle_count: 2, hidden_bundle_count: 0, hidden_bundle_edge_count: 0, element_count: nodes.length + 2, element_budget: 60, dangling_edge_count: 0 },
    cost: { edges_scanned: 0, bundles_considered: 2 },
  };
}

function renderMap(extra: Partial<Parameters<typeof GraphClusterMap>[0]> = {}) {
  getGraphClusterMap.mockImplementation((params: URLSearchParams) => Promise.resolve(frame(params)));
  const onInvestigate = vi.fn();
  const onShowEveryEdge = vi.fn();
  render(<div style={{ width: 1200, height: 800 }}><GraphClusterMap scanId="s1" narrow={false} onInvestigate={onInvestigate} onShowEveryEdge={onShowEveryEdge} {...extra} /></div>);
  return { onInvestigate, onShowEveryEdge };
}

const lastParams = () => getGraphClusterMap.mock.calls.at(-1)![0] as URLSearchParams;

describe("grouped map", () => {
  it("draws groups with counts and worst severity in words, within the first-frame budget", async () => {
    renderMap();
    await waitFor(() => expect(screen.getAllByTestId("cluster-group")).toHaveLength(4));
    const npm = screen.getAllByTestId("cluster-group").find(card => card.textContent?.includes("package:npm"))!;
    expect(npm.textContent).toContain("10 members");
    expect(npm.textContent).toContain("Worst: critical");
    expect(npm.getAttribute("data-risky")).toBe("true");
    expect(screen.getByText("1 on an attack path")).toBeTruthy();
    expect(screen.getByTestId("cluster-map-summary").textContent).toContain("4 groups of 16 nodes");
    expect(lastParams().get("scan_id")).toBe("s1");
  });

  it("expands a group in place with a pager, pages it, and collapses it back", async () => {
    renderMap();
    await waitFor(() => expect(screen.getAllByTestId("cluster-group")).toHaveLength(4));
    const npm = () => screen.getAllByTestId("cluster-group").find(card => card.textContent?.includes("package:npm"))!;
    fireEvent.click(npm());
    await waitFor(() => expect(screen.getAllByTestId("cluster-member")).toHaveLength(2));
    expect(lastParams().getAll("expand")).toEqual(["@group:package:npm"]);
    expect(screen.getByTestId("cluster-more").textContent).toContain("+8 more");
    expect(screen.getAllByTestId("cluster-frame")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Next 2" }));
    await waitFor(() => expect(screen.getByText("pkg:3")).toBeTruthy());
    expect(lastParams().getAll("page")).toEqual(["2:@group:package:npm"]);
    fireEvent.click(npm());
    await waitFor(() => expect(screen.queryAllByTestId("cluster-member")).toHaveLength(0));
    expect(lastParams().getAll("expand")).toEqual([]);
    expect(lastParams().getAll("page")).toEqual([]);
  });

  it("opens a member's connections and offers the ungrouped map", async () => {
    const { onInvestigate, onShowEveryEdge } = renderMap();
    await waitFor(() => expect(screen.getAllByTestId("cluster-group")).toHaveLength(4));
    fireEvent.click(screen.getAllByTestId("cluster-group").find(card => card.textContent?.includes("package:npm"))!);
    await waitFor(() => expect(screen.getAllByTestId("cluster-member")).toHaveLength(2));
    fireEvent.click(screen.getAllByTestId("cluster-member")[0]!);
    expect(onInvestigate).toHaveBeenCalledWith("pkg:1", "pkg:1");
    fireEvent.click(screen.getByRole("button", { name: "Show every edge" }));
    expect(onShowEveryEdge).toHaveBeenCalled();
  });

  it("shows only risky groups on request", async () => {
    renderMap();
    await waitFor(() => expect(screen.getAllByTestId("cluster-group")).toHaveLength(4));
    fireEvent.click(screen.getByRole("button", { name: "Risky groups only" }));
    await waitFor(() => expect(screen.getAllByTestId("cluster-group")).toHaveLength(3));
    expect(lastParams().get("risky_only")).toBe("true");
  });

  it("finds a node: its group opens and the node is focused", async () => {
    searchGraph.mockResolvedValue({ query: "pkg", results: [{ id: "pkg:9", label: "pkg:9", entity_type: "package" }], pagination: {} });
    renderMap();
    await waitFor(() => expect(screen.getAllByTestId("cluster-group")).toHaveLength(4));
    fireEvent.change(screen.getByLabelText("Find in grouped map"), { target: { value: "pkg" } });
    fireEvent.click(screen.getByRole("button", { name: "Find" }));
    await waitFor(() => expect(screen.getByTestId("cluster-member").getAttribute("data-focused")).toBe("true"));
    expect(lastParams().get("focus")).toBe("pkg:9");
    expect(searchGraph).toHaveBeenCalledWith("pkg", { scanId: "s1", limit: 6 });
  });

  it("hands the canvas back when the grouped read fails", async () => {
    getGraphClusterMap.mockRejectedValue(new Error("down"));
    const onUnavailable = vi.fn();
    render(<GraphClusterMap scanId="s1" narrow={false} onInvestigate={vi.fn()} onShowEveryEdge={vi.fn()} onUnavailable={onUnavailable} />);
    await waitFor(() => expect(onUnavailable).toHaveBeenCalled());
  });
});

describe("bundle emphasis", () => {
  it("lights the pointed group's bundles and quiets the rest", async () => {
    const { emphasiseBundles } = await import("@/components/graph-cluster-map");
    const edges = [{ id: "a", source: "x", target: "y" }, { id: "b", source: "y", target: "z" }, { id: "c", source: "z", target: "w" }];
    expect(emphasiseBundles(edges, null)).toBe(edges);
    expect(emphasiseBundles(edges, "y").map(edge => edge.className)).toEqual(["cluster-edge-active", "cluster-edge-active", "cluster-edge-quiet"]);
  });
});
