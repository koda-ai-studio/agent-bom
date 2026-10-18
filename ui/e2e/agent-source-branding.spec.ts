import { expect, test } from "@playwright/test";

const stamp = "2026-10-01T00:00:00Z";
const types = ["claude-code", "cursor", "codex-cli", "windsurf", "custom"];
const nodes = types.map((type, index) => ({
  id: `agent:${index}`, label: ["Review assistant", "Code assistant", "Release assistant", "Research assistant", "Local assistant"][index],
  entity_type: "agent", attributes: { agent_type: type }, severity: index === 0 ? "critical" : "none",
  risk_score: index === 0 ? 9 : 0, status: "active", data_sources: ["agent_discovery"], dimensions: {}, compliance_tags: [],
  risk_assessment: { status: "assessed", basis: "fixture finding", scope: "fixture agent" },
}));
const edges = nodes.slice(1).map(node => ({ id: `link:${node.id}`, source: "agent:0", target: node.id, relationship: "delegated_to",
  direction: "directed", weight: 1, traversable: true, first_seen: stamp, last_seen: stamp, evidence: { tier: "static_scan" } }));

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`recorded source marks retain risk and labels ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/health", route => route.fulfill({ json: { status: "ok", demo_mode: false } }));
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
      if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: "sources", created_at: stamp, node_count: nodes.length, edge_count: edges.length }] });
      if (path === "/v1/graph/query") {
        const body = route.request().postDataJSON();
        return route.fulfill({ json: { scan_id: "sources", tenant_id: "fixture", created_at: stamp, roots: body.roots, nodes, edges,
          attack_paths: [], interaction_risks: [], depth_by_node: Object.fromEntries(nodes.map((node, i) => [node.id, i ? 1 : 0])),
          truncated: false, direction: body.direction, max_depth: body.max_depth,
          stats: { total_nodes: nodes.length, total_edges: edges.length, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 9 }, budget: {} } });
      }
      return route.fulfill({ status: 404, json: { detail: "Outside fixture scope" } });
    });
    await page.goto("/graph?lens=context&scan=sources&root=agent%3A0");
    const inspector = page.getByTestId("graph-entity-drawer");
    await expect(inspector.getByRole("img", { name: "Source: Claude Code" })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`source-inspector-${theme}-${width}.png`), animations: "disabled" });
    await inspector.getByRole("button", { name: "Close", exact: true }).click();
    const views = page.getByRole("group", { name: "Investigation view" });
    // A phone opens an investigation as a list; the canvas is one tap away.
    if (await views.isVisible()) await views.getByRole("button", { name: "Graph", exact: true }).click();
    await page.getByRole("button", { name: "Fit all", exact: true }).click();
    const canvas = page.locator(".react-flow");
    for (const source of ["claude", "cursor", "openai", "windsurf"]) {
      const mark = canvas.locator(`[data-agent-source="${source}"]`);
      await expect(mark).toBeVisible();
      await expect(mark).toBeInViewport();
      expect(await mark.locator("img").evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth > 0)).toBe(true);
    }
    await expect(canvas.locator('[data-id="agent:0"] [data-severity-ring="critical"]')).toBeVisible();
    await expect(canvas.locator('[data-id="agent:4"] [data-agent-source]')).toHaveCount(0);
    await expect(canvas.locator('[data-id="agent:4"] .lucide-bot')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`agent-sources-${theme}-${width}.png`), animations: "disabled" });
  });
}
