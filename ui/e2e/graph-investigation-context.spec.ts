import { readFile } from "node:fs/promises";
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
    await expect(controls).toContainText("4 of 4 nodes in this view");
    if (width === 390) {
      await page.getByTestId("graph-entity-drawer").getByRole("button", { name: "Close", exact: true }).click();
      await expect(page.getByTestId("graph-connections-list")).toContainText("Developer agent");
      await page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true }).click();
      // The Graph view frames the loaded context; no one-node-at-a-time stepper.
      await expect(page.locator('.react-flow__node[data-id="agent"]')).toBeVisible();
      await expect(page.getByRole("group", { name: "Navigate loaded graph nodes" })).toHaveCount(0);
    }
    if (width === 390) await controls.getByLabel("Graph context", { exact: true }).selectOption("identity");
    else await controls.getByRole("button", { name: "Identity and access context", exact: true }).click();
    await expect(page.locator(".react-flow__node")).toHaveCount(2);
    await expect(controls).toContainText("2 of 4 nodes in this view");
    await expect(page).toHaveURL(/context_view=identity/);
    await expect.poll(async () => {
      const positions = await page.locator(".react-flow__node").evaluateAll(items => Object.fromEntries(items.map(n => [n.getAttribute("data-id"), { x: (n as HTMLElement).style.transform, y: n.getBoundingClientRect().y, left: n.getBoundingClientRect().x }])));
      return positions.role.left > positions.agent.left;
    }).toBe(true);
    const relationship = page.locator('.react-flow__edge[data-id="role:can_access:agent"]');
    await relationship.focus(); await relationship.press("Enter");
    await expect(page.getByLabel("Relationship details", { exact: true })).toContainText("Admin role → Developer agent");
    await page.keyboard.press("Escape");
    if (width === 390) await controls.getByLabel("Graph context", { exact: true }).selectOption("all");
    else await controls.getByRole("button", { name: "All relationships", exact: true }).click();
    await expect(page.locator(".react-flow__node")).toHaveCount(4);
    if (width === 390) {
      await page.waitForTimeout(1000);
      const captionCrossings = await page.locator(".react-flow").evaluate(canvas => {
        const card = canvas.querySelector('.react-flow__node[data-id="agent"] [data-graph-entity]')!;
        const captions = [...card.children].slice(1).filter(child => getComputedStyle(child).display !== "none" && getComputedStyle(child).visibility !== "hidden").map(child => child.getBoundingClientRect());
        return [...canvas.querySelectorAll<SVGPathElement>(".react-flow__edge-path")].filter(path => {
          const matrix = path.getScreenCTM()!;
          for (let distance = 0; distance <= path.getTotalLength(); distance += 2) {
            const point = path.getPointAtLength(distance).matrixTransform(matrix);
            if (captions.some(box => point.x > box.left + 1 && point.x < box.right - 1 && point.y > box.top + 1 && point.y < box.bottom - 1)) return true;
          }
          return false;
        }).map(path => path.closest(".react-flow__edge")?.getAttribute("data-id"));
      });
      expect(captionCrossings).toEqual([]);
    }
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

for (const theme of ["light", "dark"]) test(`fit all includes complete shared-server connectors ${theme}`, async ({ page }, info) => {
  await page.setViewportSize({ width: 1440, height: 820 });
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  const nodes = [node("role", "role", "prod-ai-admin"), node("agent", "agent", "Developer Copilot"), node("peer", "agent", "Sre Runbook Agent"), node("github", "server", "github-enterprise MCP"), node("filesystem", "server", "filesystem MCP")].map(n => ({ ...n, dimensions: { environment: "prod" } }));
  await fixture(page, nodes, [edge("role", "agent", "can_access"), edge("agent", "github", "uses"), edge("agent", "filesystem", "uses"), edge("agent", "peer", "shares_server"), edge("peer", "filesystem", "uses")]);
  await page.goto("/graph?scan=snapshot&root=agent&lens=context&capture=1");
  await expect(page.locator(".react-flow__node")).toHaveCount(5);
  await page.getByTestId("graph-entity-drawer").getByRole("button", { name: "Close", exact: true }).click();
  await page.locator(".react-flow__controls-fitview").click();
  let previousViewport = "";
  let stableSamples = 0;
  await expect.poll(async () => {
    const current = await page.locator(".react-flow__viewport").evaluate(element => getComputedStyle(element).transform);
    stableSamples = current === previousViewport ? stableSamples + 1 : 0;
    previousViewport = current;
    return stableSamples;
  }, { intervals: [100] }).toBeGreaterThanOrEqual(4);
  await expect.poll(() => page.locator(".react-flow").evaluate(canvas => {
    const bounds = canvas.getBoundingClientRect();
    return [...canvas.querySelectorAll(".react-flow__edge-path, .graph-relationship-label, .react-flow__node [data-graph-entity]")].filter(element => {
      const r = element.getBoundingClientRect();
      return r.width && r.height && (r.left < bounds.left || r.right > bounds.right || r.top < bounds.top || r.bottom > bounds.bottom);
    }).map(element => element.getAttribute("data-edge-id") ?? element.id ?? String(element.className));
  })).toEqual([]);
  const overlaps = await page.locator("[data-graph-entity]").evaluateAll(cards => {
    const boxes = cards.map(card => {
      const parts = [...card.children].filter(child => getComputedStyle(child).visibility !== "hidden" && getComputedStyle(child).display !== "none").map(child => child.getBoundingClientRect());
      return { label: card.getAttribute("title"), left: Math.min(...parts.map(r => r.left)), right: Math.max(...parts.map(r => r.right)), top: Math.min(...parts.map(r => r.top)), bottom: Math.max(...parts.map(r => r.bottom)) };
    });
    return boxes.flatMap((a, i) => boxes.slice(i + 1).filter(b => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top).map(b => [a.label, b.label]));
  });
  expect(overlaps).toEqual([]);
  const titleLines = await page.locator("[data-graph-entity] > p").evaluateAll(titles => titles.map(title => {
    const zoom = new DOMMatrixReadOnly(getComputedStyle(title.closest(".react-flow__viewport")!).transform).a;
    return title.getBoundingClientRect().height / (parseFloat(getComputedStyle(title).lineHeight) * zoom);
  }));
  expect(Math.max(...titleLines)).toBeLessThanOrEqual(2.1);
  const primaryFonts = await page.locator(".react-flow__node").evaluateAll(nodes => nodes.map(node => {
    const viewport = node.closest(".react-flow__viewport")!;
    const zoom = new DOMMatrixReadOnly(getComputedStyle(viewport).transform).a;
    return Math.max(0, ...[...node.querySelectorAll("span, p")].filter(text => text.textContent?.trim()).map(text => parseFloat(getComputedStyle(text).fontSize) * zoom));
  }));
  expect(Math.min(...primaryFonts)).toBeGreaterThanOrEqual(12);
  const badgeFonts = await page.locator(".react-flow__node [data-node-badge]").evaluateAll(badges => badges.map(badge => {
    const transform = getComputedStyle(badge.closest(".react-flow__viewport")!).transform;
    return parseFloat(getComputedStyle(badge).fontSize) * new DOMMatrixReadOnly(transform).a;
  }));
  expect(badgeFonts.length).toBeGreaterThan(0);
  expect(Math.min(...badgeFonts)).toBeGreaterThanOrEqual(11);
  await page.screenshot({ path: info.outputPath(`shared-server-${theme}.png`), animations: "disabled" });
});

for (const theme of ["light", "dark"]) test(`complete correlation captions remain inside Fit all ${theme}`, async ({ page }, info) => {
  const proof = JSON.parse(await readFile("../examples/reference-evidence-lab/generated/correlation-proof.json", "utf8"));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  await fixture(page, proof.capture_fixture.graph.nodes, proof.capture_fixture.graph.edges, true);
  await page.goto("/graph?capture=1&scan=snapshot&layers=server,agent,container,package,vulnerability,tool,serviceAccount,dataStore,sourceFile");
  await expect(page.locator(".react-flow__node")).toHaveCount(10);
  await page.locator(".react-flow__controls-fitview").click();
  await expect.poll(() => page.locator(".react-flow").evaluate(canvas => {
    const bounds = canvas.getBoundingClientRect();
    return [...canvas.querySelectorAll("[data-graph-entity]")].filter(element => {
      const r = element.getBoundingClientRect();
      return r.left < bounds.left || r.right > bounds.right || r.top < bounds.top || r.bottom > bounds.bottom;
    }).map(element => ({ label: element.getAttribute("title"), bounds: element.getBoundingClientRect().toJSON(), canvas: bounds.toJSON() }));
  })).toEqual([]);
  await page.screenshot({ path: info.outputPath(`complete-correlation-${theme}.png`), animations: "disabled" });
});


test("larger investigation captions stay inside ordinary layout cards", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 820 });
  const servers = Array.from({ length: 15 }, (_, i) => node(`server-${i}`, "server", `Server ${i}`));
  await fixture(page, [node("role", "role", "prod-ai-admin"), node("agent", "agent", "Developer Copilot"), ...servers],
    [edge("role", "agent", "can_access"), ...servers.map(server => edge("agent", server.id, "uses"))]);
  await page.goto("/graph?scan=snapshot&root=agent&lens=context&capture=1");
  // Fifteen sibling servers arrive as one group; expanding restores every card.
  await page.getByRole("button", { name: "Expand 15 members", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(17);
  await expect.poll(() => page.locator("[data-graph-entity]").evaluateAll(cards =>
    Math.max(...cards.map(card => parseFloat(getComputedStyle(card).width))))).toBeLessThanOrEqual(240);
  const agent = page.locator('.react-flow__node[data-id="agent"]');
  await expect.poll(async () => {
    const hostSize = await agent.getByText("Host not recorded", { exact: true }).evaluate(el => parseFloat(getComputedStyle(el).fontSize));
    const kindSize = await agent.getByText("Agent kind not recorded", { exact: true }).evaluate(el => parseFloat(getComputedStyle(el).fontSize));
    return hostSize / kindSize;
  }, { message: "Host context uses the same zoom-readable type size as the agent kind" }).toBeGreaterThanOrEqual(0.95);
});

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`agent platform and membership do not imply deployment ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    const agent = { ...node("agent", "agent", "Support workflow"), attributes: { agent_type: "workflow" } };
    const environment = { ...node("environment", "environment", "Production AI"), attributes: { cloud_provider: "aws" } };
    await fixture(page, [agent, environment, node("platform", "provider", "Custom workflow")], [edge("environment", "agent", "contains"), edge("platform", "agent", "platform_for")]);
    await page.goto("/graph?scan=snapshot&root=agent&lens=context");
    const context = page.getByLabel("Agent execution and model context", { exact: true });
    await expect(context).toBeVisible();
    await expect(context.getByRole("region", { name: "Platform association", exact: true })).toContainText("Custom workflow");
    await expect(context.getByRole("region", { name: "Execution host", exact: true })).toContainText("Not recorded in this evidence");
    await expect(context.getByRole("region", { name: "Model links", exact: true })).toContainText("Not recorded in this evidence");
    await expect(context.getByRole("region", { name: "Environment membership", exact: true })).toContainText("Production AI");
    await expect(context).toContainText("does not prove runtime execution");
    if (width === 1440) {
      await expect(page.locator('.react-flow__node[data-id="agent"]')).toContainText("Host not recorded");
      await expect(page.getByText("Includes · membership", { exact: true })).toBeVisible();
    }
    await page.screenshot({ path: info.outputPath(`agent-context-${theme}-${width}.png`), fullPage: true });
  });
}
