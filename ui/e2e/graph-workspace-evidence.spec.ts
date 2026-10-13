import { expect, test, type Page } from "@playwright/test";

// Contracts formerly exercised through separate Context/Mesh canvases now use
// the same bounded query, selection, and relationship inspector as other links.
const root = "agent:root";
const stamp = "2026-10-12T00:00:00Z";
const observed = "2026-09-01T00:00:00Z";
const node = (id: string, entity_type = "server", attributes = {}) => ({ id, label: id.split(":").at(-1), entity_type, attributes, severity: "none", risk_score: 0, status: "active", data_sources: ["fixture"], dimensions: {}, compliance_tags: [] });
const role = node("role:conditional", "role", { admin_equivalence_status: "conditional_admin", admin_equivalence_resource_scopes: ["arn:aws:iam::123456789012:*"] });
const nodes = [node(root, "agent"), role, ...Array.from({ length: 30 }, (_, i) => node(`server:${i}`))];
const edges = nodes.slice(1).map(n => ({ id: `edge:${n.id}`, source: root, target: n.id, relationship: n.id === role.id ? "assumes" : "uses", direction: "bidirectional", weight: 1, traversable: false, first_seen: stamp, last_seen: stamp, evidence: { basis: "configured", observed_at: observed, packages: ["fixture-package@1.0"] } }));
async function fixture(page: Page) {
  const queries: Array<{roots: string[]; max_nodes: number; direction: string; scan_id: string}> = [];
  await page.route("**/health", route => route.fulfill({json: {status: "ok", demo_mode: false}}));
  await page.route("**/v1/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname === "/v1/auth/me") return route.fulfill({json: {authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth"}});
    if (url.pathname === "/v1/graph/snapshots") return route.fulfill({json: [{scan_id: "snapshot", created_at: stamp, node_count: nodes.length, edge_count: edges.length}]});
    if (url.pathname === "/v1/graph/query") {
      const body = route.request().postDataJSON(); queries.push(body);
      const selected = body.roots[0] === root ? nodes.slice(0, body.max_nodes) : [nodes.find(n => n.id === body.roots[0])!, nodes[0]!];
      const ids = new Set(selected.map(n => n.id));
      const relations = edges.filter(e => ids.has(e.source) && ids.has(e.target));
      return route.fulfill({json: {scan_id: body.scan_id, tenant_id: "fixture", created_at: stamp, roots: body.roots, nodes: selected, edges: relations, attack_paths: [], interaction_risks: [], depth_by_node: Object.fromEntries(selected.map(n => [n.id, n.id === body.roots[0] ? 0 : 1])), truncated: body.roots[0] === root, direction: body.direction, max_depth: body.max_depth, stats: {total_nodes: selected.length, total_edges: relations.length, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0}, budget: {}}});
    }
    return route.fulfill({status: 404, json: {detail: "Outside recorded fixture"}});
  });
  return queries;
}
for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`shared workspace bounds expansion and preserves conditional evidence ${theme} ${width}`, async ({page}, testInfo) => {
    await page.setViewportSize({width, height: 1000});
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const queries = await fixture(page);
    await page.goto(`/graph?lens=context&scan=snapshot&root=${root}`);
    const inspector = page.getByTestId("graph-entity-drawer");
    await expect(inspector.getByRole("heading", {name: "root", exact: true})).toBeVisible();
    expect(queries[0]?.max_nodes).toBe(4);
    await expect(page.locator(".react-flow__node")).toHaveCount(4);
    if (width === 390) await inspector.getByRole("button", {name: "Close", exact: true}).click();
    await page.getByRole("button", {name: "Show more connections", exact: true}).click();
    await expect(page.locator(".react-flow__node")).toHaveCount(8);
    expect(queries.at(-1)?.max_nodes).toBe(8);
    if (width === 390 && await inspector.isVisible()) await inspector.getByRole("button", {name: "Close", exact: true}).click();
    expect(queries.every(q => q.scan_id === "snapshot" && q.roots[0] === root)).toBe(true);
    // Selecting a recorded node does not implicitly fetch or expand its graph.
    const count = queries.length;
    await page.locator('[data-id="role:conditional"]').click();
    await expect(inspector.getByText("Conditional admin", {exact: true})).toBeVisible();
    await expect(inspector.getByText(/request context has not been verified/)).toBeVisible();
    await expect(inspector.getByText(/Scope: arn:aws:iam/)).toBeVisible();
    expect(queries).toHaveLength(count);
    if (width === 390) await inspector.getByRole("button", {name: "Close", exact: true}).click();
    const edge = page.locator('.react-flow__edge[data-id="edge:role:conditional"]');
    await edge.focus(); await edge.press("Space");
    const receipt = page.getByLabel("Relationship details", {exact: true});
    await expect(receipt.getByText("root ↔ conditional", {exact: true})).toBeVisible();
    await expect(receipt.getByText(/does not establish execution/)).toBeVisible();
    await receipt.getByText("Recorded evidence", {exact: true}).click();
    await expect(receipt.getByText(/fixture-package@1.0/)).toBeVisible();
    await page.keyboard.press("Escape"); await expect(edge).toBeFocused();
    const usageEdge = page.locator('.react-flow__edge[data-id="edge:server:0"]');
    await usageEdge.focus(); await usageEdge.press("Space");
    await expect(receipt.getByRole("region", { name: "Why linked" })).toContainText("It does not establish that a tool was called.");
    await expect(receipt.getByLabel("Recorded link evidence")).toContainText("configured");
    const freshness = receipt.getByLabel("Relationship evidence and freshness");
    await expect(freshness).toContainText("Static / configured");
    await expect(freshness).toContainText(observed);
    await expect(freshness).toContainText(stamp);
    await expect(receipt.getByText(/Traversal eligibility does not establish runtime reachability/)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({path: testInfo.outputPath(`relationship-explanation-${theme}-${width}.png`), animations: "disabled"});
    await page.keyboard.press("Escape"); await expect(usageEdge).toBeFocused();
    // A new canonical root replaces the bounded window, without old branches.
    await page.evaluate(() => history.pushState(null, "", "/graph?lens=mesh&scan=snapshot&root=role%3Aconditional"));
    await expect(inspector.getByRole("heading", {name: "conditional", exact: true})).toBeVisible();
    await expect(page.locator(".react-flow__node")).toHaveCount(2);
    expect(queries.at(-1)?.roots).toEqual([role.id]);
    await expect(page.getByRole("link", {name: "Inspect in lineage"})).toHaveCount(0);
    if (width === 390) {
      const dialog = page.getByRole("dialog", { name: "conditional", exact: true });
      await expect(dialog).toHaveCSS("opacity", "1");
      await page.screenshot({path: testInfo.outputPath(`shared-detail-${theme}-${width}.png`), animations: "disabled"});
      await inspector.getByRole("button", {name: "Close", exact: true}).click();
    }
    await expect.poll(async () => {
      const selected = await page.locator('[data-id="role:conditional"].react-flow__node').boundingBox();
      const canvas = await page.locator(".react-flow").boundingBox();
      return Boolean(selected && canvas && selected.width >= 140 && selected.x >= canvas.x &&
        selected.x + selected.width <= canvas.x + canvas.width && selected.y >= canvas.y &&
        selected.y + selected.height <= canvas.y + canvas.height);
    }).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    const heading = await page.getByRole("heading", { name: "Investigation", exact: true }).boundingBox();
    const header = await page.getByRole("banner").boundingBox();
    expect(heading!.y).toBeGreaterThanOrEqual(header!.y + header!.height);
    await page.screenshot({path: testInfo.outputPath(`shared-evidence-${theme}-${width}.png`), fullPage: true, animations: "disabled"});
  });
}
