import { expect, test } from "@playwright/test";
import topology from "./fixtures/terraform-real-topology.json";

for (const width of [1440, 390]) for (const theme of ["light", "dark"]) {
  test(`real Terraform topology opens with readable connected nodes at ${width}px in ${theme}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(theme => localStorage.setItem("agent-bom-theme", theme), theme);
    const stamp = "2026-11-03T00:00:00Z";
    await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", r => {
      const url = new URL(r.request().url());
      if (url.pathname === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
      if (url.pathname === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "terraform", created_at: stamp, node_count: topology.nodes.length, edge_count: topology.edges.length }] });
      if (url.pathname === "/v1/graph") return r.fulfill({ json: { scan_id: "terraform", tenant_id: "fixture", created_at: stamp, nodes: topology.nodes, edges: topology.edges, attack_paths: [], interaction_risks: [], pagination: { total: topology.nodes.length, offset: 0, limit: 100, returned: topology.nodes.length, has_more: false }, completeness: { complete: true, truncated: false, returned: topology.nodes.length, total: topology.nodes.length }, stats: { total_nodes: topology.nodes.length, total_edges: topology.edges.length, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 } } });
      return r.fulfill({ status: 404, json: { detail: "Outside static topology fixture" } });
    });
    await page.goto("/graph?scan=terraform&rollup=0");
    if (width < 640) {
      await expect(page.getByRole("group", { name: "Investigation view" })).toBeVisible();
      await page.screenshot({ path: info.outputPath(`terraform-${width}-${theme}-list.png`), fullPage: true });
      await page.getByRole("button", { name: "Graph", exact: true }).click();
    }
    const nodes = page.locator(".react-flow__node");
    await expect(nodes.first()).toBeVisible();
    // The previous first view rendered 50 nodes, rectangular summary labels,
    // and clipped most branches. A preview must disclose its bounded scope.
    await expect(page.getByRole("group", { name: "Connection preview" })).toBeVisible();
    await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
    expect(await nodes.count()).toBeGreaterThan(1);
    expect(await nodes.count()).toBeLessThanOrEqual(6);
    await expect(page.locator(".react-flow__node .graph-entity-glyph")).toHaveCount(await nodes.count());
    expect(await nodes.evaluateAll(items => items.every(item => {
      const box = item.getBoundingClientRect(), frame = item.closest(".react-flow")!.getBoundingClientRect();
      return box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
    }))).toBe(true);
    await expect(page.locator(".react-flow__edge").first()).toBeVisible();
    await page.screenshot({ path: info.outputPath(`terraform-${width}-${theme}.png`), fullPage: true });
    await page.getByRole("button", { name: /Show full map/ }).click();
    await expect(nodes).toHaveCount(50);
    await page.reload();
    if (width < 640) await page.getByRole("button", { name: "Graph", exact: true }).click();
    await expect(nodes).toHaveCount(50);
    await page.getByRole("button", { name: "Return to connection preview" }).click();
    await expect(nodes).toHaveCount(width < 640 ? 2 : 6);
    const repository = topology.nodes.find(node => node.label === "Project root")!;
    await page.getByRole("combobox", { name: "Preview starting point" }).selectOption(repository.id);
    await expect(page.locator(`.react-flow__node[data-id="${repository.id}"]`)).toBeVisible();
    await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
    expect(await nodes.count()).toBeLessThanOrEqual(width < 640 ? 2 : 6);
  });
}
