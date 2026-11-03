import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`connected scope preview stays readable and retains full navigation ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    const created_at = "2026-11-03T09:00:00Z", scan_id = "scope-preview";
    const aggregate = { descendant_count: 0, by_type: {}, severity_counts: {}, worst_severity: "none", worst_severity_rank: 0,
      internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 };
    const items = ["Deploy service", "Worker service"].flatMap((label, owner) => [
      { id: `app-${owner}`, label, entity_type: "application", severity: "none" },
      ...Array.from({ length: 14 }, (_, i) => ({ id: `finding-${owner}-${i}`, label: ["Public endpoint allows anonymous access", "Container runs as root", "Storage encryption is disabled"][i % 3]! + ` ${i}`, entity_type: "misconfiguration", severity: "high" })),
    ]).map(item => ({ ...item, is_container: false, has_children: false, direct_child_count: 0, aggregate }));
    const edges = items.filter(item => item.entity_type === "misconfiguration").map(item => ({ source: item.id, target: `app-${item.id.split("-")[1]}`, count: 1, relationships: ["belongs_to"], directions: ["directed"] }));
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
      if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id, created_at, node_count: 500, edge_count: 600 }] });
      if (path === "/v1/graph/rollup") return route.fulfill({ json: { scan_id, created_at, tenant_id: "fixture", mode: "rollup", filters: {}, top_level: items, edges, summary: { total_nodes: 500, total_edges: 600, top_level_count: 30 }, completeness: { truncated: true, returned: 30, total: 500 } } });
      if (path === "/v1/graph") return route.fulfill({ json: { scan_id, created_at, nodes: items.map(item => ({ ...item, attributes: {}, dimensions: {}, data_sources: ["fixture"] })), edges: [], attack_paths: [], interaction_risks: [], stats: { total_nodes: 500, total_edges: 600, node_counts: {}, edge_counts: {}, severity_counts: {} }, completeness: { truncated: true, returned: 30, total: 500 } } });
      return route.fulfill({ status: 404, json: { detail: "Outside fixture" } });
    });
    await page.goto(`/graph?scan=${scan_id}&rollup=1`);
    const overview = page.getByTestId("graph-scope-overview"), canvas = page.getByTestId("graph-scope-connections");
    await expect(overview).toBeVisible();
    await expect(canvas.locator(".react-flow__node")).toHaveCount(4);
    await expect(canvas.locator(".react-flow__edge")).toHaveCount(3);
    await expect(overview).toContainText("3 of 14 loaded relationships");
    await page.waitForLoadState("networkidle");
    expect(await canvas.locator(".react-flow__node").evaluateAll(nodes => nodes.every(node => {
      const box = node.getBoundingClientRect(), frame = node.closest(".react-flow")!.getBoundingClientRect();
      const label = node.querySelector("p")!;
      const zoom = box.width / (node as HTMLElement).offsetWidth;
      return box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom && parseFloat(getComputedStyle(label).fontSize) * zoom >= 12;
    }))).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(await canvas.locator(".react-flow__node").evaluateAll(nodes => nodes.every(node => {
      const box = node.getBoundingClientRect(), frame = node.closest("[data-graph-adaptive-frame]")!.getBoundingClientRect();
      return box.top >= frame.top && box.bottom <= frame.bottom;
    }))).toBe(true);
    await page.screenshot({ path: info.outputPath(`scope-preview-${theme}-${width}.png`), fullPage: true });
    await page.getByLabel("Connection scope").selectOption("app-1");
    await expect(canvas.locator('[data-id="app-1"]')).toBeVisible();
    await overview.getByRole("button", { name: "Browse all 30 nodes and scopes" }).click();
    await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
    await overview.getByRole("button", { name: "Show connections" }).click();
    await expect(page.getByLabel("Connection scope")).toHaveValue("app-1");
  });
}
