import { test, expect, type Page } from "@playwright/test";
const stamp = "2026-10-15T00:00:00Z";
const node = (id: string, entity_type: string, label = id) => ({ id, entity_type, label, severity: "none", status: "active", risk_score: 0, attributes: {}, dimensions: {}, data_sources: ["synthetic-fixture"], compliance_tags: [] });
const edge = (source: string, target: string, relationship: string) => ({ id: `${source}:${relationship}:${target}`, source, target, relationship, direction: "directed", traversable: true, weight: 1, evidence: { tier: "static_scan", source: "synthetic-fixture" }, first_seen: stamp, last_seen: stamp });
async function fixture(page: Page, nodes: ReturnType<typeof node>[], edges: ReturnType<typeof edge>[], correlation = false) {
  const graph = { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, nodes, edges, attack_paths: [], interaction_risks: [], stats: { total_nodes: nodes.length, total_edges: edges.length, severity_counts: {} } };
  await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", r => {
    const u = new URL(r.request().url());
    if (u.pathname === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (u.pathname === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "snapshot", created_at: stamp, snapshot_kind: correlation ? "correlation" : "scan", node_count: nodes.length, edge_count: edges.length }] });
    if (u.pathname === "/v1/graph") return r.fulfill({ json: { ...graph, pagination: { total: nodes.length, offset: 0, limit: 100, returned: nodes.length, has_more: false } } });
    if (u.pathname === "/v1/graph/query") return r.fulfill({ json: { ...graph, roots: ["agent"], depth_by_node: { agent: 0 }, truncated: false, direction: "both", max_depth: 1, budget: {} } });
    if (u.pathname.startsWith("/v1/graph/node/")) {
      const id = decodeURIComponent(u.pathname.split("/").at(-1)!);
      return r.fulfill({ json: { node: nodes.find(n => n.id === id), sources: [], edges_in: edges.filter(e => e.target === id), edges_out: edges.filter(e => e.source === id), neighbors: [], impact: { node_id: id, affected_nodes: [], affected_by_type: {}, affected_count: 0, max_depth_reached: 0 }, completeness: { complete: true } } });
    }
    if (u.pathname === "/v1/graph/rollup") return r.fulfill({ json: { ...graph, mode: "rollup", top_level: [], children: [], summary: { total_nodes: nodes.length }, completeness: { complete: true }, pagination: { offset: 0, limit: 100, total: 0, returned: 0, has_more: false } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}
for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`agent anchor and incoming identity context ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    const nodes = [node("role", "role", "Admin role"), node("agent", "agent", "Developer agent"), node("github", "server", "GitHub MCP"), node("filesystem", "server", "Filesystem MCP")];
    await fixture(page, nodes, [edge("role", "agent", "can_access"), edge("agent", "github", "uses"), edge("agent", "filesystem", "uses")]);
    await page.goto("/graph?scan=snapshot&root=agent&lens=context");
    const controls = page.getByLabel("Investigation context", { exact: true });
    await expect(controls).toBeVisible();
    await expect(controls).toContainText("4 of 4 loaded nodes shown");
    if (width === 390) {
      await page.getByTestId("graph-entity-drawer").getByRole("button", { name: "Close", exact: true }).click();
      await expect(page.getByRole("group", { name: "Navigate loaded graph nodes" })).toContainText("Developer agent");
    }
    if (width === 390) await controls.getByLabel("Graph context", { exact: true }).selectOption("identity");
    else await controls.getByRole("button", { name: "Identity and access context", exact: true }).click();
    await expect(page.locator(".react-flow__node")).toHaveCount(2);
    await expect(controls).toContainText("2 of 4 loaded nodes shown");
    await expect(page).toHaveURL(/context_view=identity/);
    await expect.poll(async () => {
      const positions = await page.locator(".react-flow__node").evaluateAll(items => Object.fromEntries(items.map(n => [n.getAttribute("data-id"), { x: (n as HTMLElement).style.transform, y: n.getBoundingClientRect().y, left: n.getBoundingClientRect().x }])));
      return width >= 640 ? positions.role.left > positions.agent.left : positions.role.y > positions.agent.y;
    }).toBe(true);
    const relationship = page.locator('.react-flow__edge[data-id="role:can_access:agent"]');
    await relationship.focus(); await relationship.press("Enter");
    await expect(page.getByLabel("Relationship details", { exact: true })).toContainText("Admin role → Developer agent");
    await page.keyboard.press("Escape");
    if (width === 390) await controls.getByLabel("Graph context", { exact: true }).selectOption("all");
    else await controls.getByRole("button", { name: "All relationships", exact: true }).click();
    await expect(page.locator(".react-flow__node")).toHaveCount(4);
    await page.locator(".react-flow").scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath(`agent-context-${theme}-${width}.png`), animations: "disabled" });
  });
}
for (const theme of ["light", "dark"]) test(`correlation opens a coherent dependency context ${theme}`, async ({ page }, info) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  const nodes = [node("manifest", "source_file"), node("image", "container"), node("deployment", "container"), node("package", "package"), node("finding", "vulnerability"), node("agent", "agent")];
  await fixture(page, nodes, [edge("manifest", "package", "contains"), edge("image", "package", "contains"), edge("deployment", "package", "contains"), edge("package", "finding", "vulnerable_to"), edge("deployment", "agent", "hosts")], true);
  await page.goto("/graph?scan=snapshot&lens=estate&rollup=0");
  const controls = page.getByLabel("Investigation context", { exact: true });
  await expect(controls.getByRole("button", { name: "Dependency evidence", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".react-flow__node")).toHaveCount(5);
  await expect(controls).toContainText("1 relationship crosses groups");
  await page.screenshot({ path: info.outputPath(`dependency-context-${theme}.png`), animations: "disabled" });
  await page.locator('.react-flow__node[data-id="package"]').click();
  await expect(page.getByTestId("graph-entity-drawer")).toBeVisible();
  await controls.getByRole("button", { name: "Workload and access context", exact: true }).click();
  await expect(page.getByTestId("graph-entity-drawer")).toHaveCount(0);
  await expect(page.locator(".react-flow__node")).toHaveCount(1);
  await controls.getByRole("button", { name: "All relationships", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(6);
  await page.reload();
  await expect(page.locator(".react-flow__node")).toHaveCount(6);
  await page.screenshot({ path: info.outputPath(`correlation-context-${theme}.png`), animations: "disabled" });
});
