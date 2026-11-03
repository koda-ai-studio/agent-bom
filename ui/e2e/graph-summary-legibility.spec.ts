import { expect, test } from "@playwright/test";

test("compact inventory names remain readable after zooming out", async ({ page }) => {
  const stamp = "2026-11-03T09:00:00Z";
  const nodes = Array.from({ length: 30 }, (_, i) => ({ id: `pkg-${i}`, label: `package-${i}`, entity_type: "package", severity: "none", status: "active", risk_score: 0, attributes: {}, dimensions: {}, data_sources: ["fixture"] }));
  const edges = nodes.slice(1).map((node, i) => ({ id: `edge-${i}`, source: nodes[i]!.id, target: node.id, relationship: "depends_on", direction: "directed", weight: 1, traversable: true, evidence: { tier: "static_scan" }, first_seen: stamp, last_seen: stamp }));
  await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: "summary", created_at: stamp, node_count: nodes.length, edge_count: edges.length }] });
    if (path === "/v1/graph") return route.fulfill({ json: { scan_id: "summary", created_at: stamp, nodes, edges, pagination: { total: nodes.length, offset: 0, limit: 100, returned: nodes.length, has_more: false }, completeness: { complete: true, truncated: false, total: nodes.length, returned: nodes.length }, attack_paths: [], interaction_risks: [], stats: { total_nodes: nodes.length, total_edges: edges.length, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 } } });
    return route.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
  await page.goto("/graph?scan=summary&rollup=0&layers=package");
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  await page.getByRole("button", { name: "Show full map (30)" }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(30);
  // An explicit user zoom selects the summary renderer without changing data.
  await page.getByRole("button", { name: /zoom out/i }).click();
  await expect(page.getByTestId("summary-node").first()).toBeAttached();
  expect(await page.getByTestId("summary-node").first().evaluate(node => {
    const label = node.querySelector("span")!, flowNode = node.closest(".react-flow__node")! as HTMLElement;
    const scale = flowNode.getBoundingClientRect().width / flowNode.offsetWidth;
    return parseFloat(getComputedStyle(label).fontSize) * scale;
  })).toBeGreaterThanOrEqual(12);
  await expect(page.getByTestId("summary-node").first()).toHaveAttribute("title", /package-/);
});
