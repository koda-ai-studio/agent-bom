import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect, type Page } from "@playwright/test";

type Graph = { nodes: { id: string; label: string }[]; edges: { id: string; source: string; target: string }[] };
const fixtures = JSON.parse(readFileSync(join(__dirname, "fixtures/k8s-projection.json"), "utf8")) as Record<string, Graph>;
const stamp = "2026-11-05T00:00:00Z";

async function serve(page: Page, graph: Graph) {
  const body = { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, ...graph, attack_paths: [], interaction_risks: [], stats: { total_nodes: graph.nodes.length, total_edges: graph.edges.length, severity_counts: {} } };
  const clusterReads: string[] = [];
  await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", r => {
    const path = new URL(r.request().url()).pathname;
    if (path === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (path === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "snapshot", created_at: stamp, snapshot_kind: "scan", node_count: graph.nodes.length, edge_count: graph.edges.length }] });
    if (path === "/v1/graph") return r.fulfill({ json: { ...body, pagination: { total: graph.nodes.length, offset: 0, limit: 100, returned: graph.nodes.length, has_more: false } } });
    if (path === "/v1/graph/cluster-map") { clusterReads.push(path); return r.fulfill({ status: 503, json: { detail: "Grouped map unavailable" } }); }
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
  return clusterReads;
}

test("a failed grouped read falls back without turning grouping off for the reader", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const clusterReads = await serve(page, fixtures.clusterEstate!);
  await page.goto("/security-graph?scan=snapshot&lens=estate&rollup=0&map_view=full");
  await expect.poll(() => clusterReads.length).toBeGreaterThan(0);
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  // The reader never chose the ungrouped map: no preference is written and nothing offers to undo one.
  expect(new URL(page.url()).searchParams.get("grouping")).toBeNull();
  await expect(page.getByTestId("regroup-map")).toHaveCount(0);
});
