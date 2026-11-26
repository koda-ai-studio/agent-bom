import type { Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import fixture from "../../tests/fixtures/product-proof-rollup.json";
const graphFixture = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e",
  'import { buildGraph } from "./scripts/product-proof-graph.mjs"; import { graphImpact } from "./scripts/static-demo-routes.mjs"; const graph=buildGraph(); process.stdout.write(JSON.stringify({ graph, impacts: Object.fromEntries(graph.nodes.map(node => [node.id, graphImpact(graph,node.id)])) }));'], { encoding: "utf8" }));


export async function installAgentScopeFixture(page: Page) {
    const graph = graphFixture.graph;
    const queries: { roots: string[] }[] = [];
    const errors: string[] = []; page.on("pageerror", error => errors.push(error.message));
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url()), path = url.pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: graph.tenant_id, role: "admin", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
      if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: graph.scan_id, created_at: graph.created_at, node_count: graph.nodes.length, edge_count: graph.edges.length }] });
      if (path === "/v1/graph/rollup") return route.fulfill({ json: fixture.rollup });
      if (path === "/v1/graph/node-aggregates") return route.fulfill({ json: { scan_id: graph.scan_id, snapshot_generation: url.searchParams.get("snapshot_generation"), aggregates: url.searchParams.getAll("node_id").map(node_id => ({ node_id, ...fixture.node_aggregates[node_id as keyof typeof fixture.node_aggregates] })), missing_node_ids: [] } });
      if (path === "/v1/graph/scope-findings") {
        const id = url.searchParams.get("node_id") as keyof typeof fixture.scope_findings;
        const findings = fixture.scope_findings[id];
        return route.fulfill({ json: { scan_id: graph.scan_id, snapshot_generation: "proof", finding_revision: "proof", node_id: id, total: findings.length, offset: 0, limit: 20, findings } });
      }
      if (path === "/v1/graph") return route.fulfill({ json: graph });
      if (path === "/v1/graph/query") {
        const request = route.request().postDataJSON(); queries.push(request);
        const depth = new Map<string, number>(request.roots.map((id: string) => [id, 0]));
        const queue = [...depth.keys()];
        for (let index = 0; index < queue.length; index++) {
          const id = queue[index]!;
          if (depth.get(id)! >= request.max_depth) continue;
          for (const edge of graph.edges) {
            const next = edge.source === id && request.direction !== "reverse" ? edge.target : edge.target === id && request.direction !== "forward" ? edge.source : null;
            if (next && !depth.has(next)) { depth.set(next, depth.get(id)! + 1); queue.push(next); }
          }
        }
        const ids = new Set(queue.slice(0, request.max_nodes));
        return route.fulfill({ json: { ...graph, nodes: graph.nodes.filter((node: { id: string }) => ids.has(node.id)),
          edges: graph.edges.filter((edge: { source: string; target: string }) => ids.has(edge.source) && ids.has(edge.target)),
          roots: request.roots, direction: request.direction, truncated: queue.length > ids.size, missing_roots: [], depth_by_node: Object.fromEntries(depth), filters: {}, completeness: { truncated: queue.length > ids.size } } });
      }
      if (path.startsWith("/v1/graph/node/")) {
        const id = decodeURIComponent(path.split("/").at(-1)!);
        const node = graph.nodes.find((node: { id: string }) => node.id === id);
        return route.fulfill({ json: { node, edges_out: graph.edges.filter((edge: { source: string }) => edge.source === id), edges_in: graph.edges.filter((edge: { target: string }) => edge.target === id), neighbors: [], sources: [], impact: graphFixture.impacts[id] } });
      }
      return route.fulfill({ status: 404, json: { detail: "Outside fixture" } });
    });
    return { graph, queries, errors };
}
