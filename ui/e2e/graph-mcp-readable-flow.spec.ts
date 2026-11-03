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
    if (u.pathname === "/v1/graph/attack-paths") return r.fulfill({ json: { ...graph, nodes: [], edges: [], attack_paths: [], pagination: { total: 0, offset: 0, limit: 10, returned: 0, has_more: false } } });
    if (u.pathname === "/v1/graph/rollup") return r.fulfill({ json: { ...graph, mode: "rollup", top_level: [], children: [], summary: { total_nodes: nodes.length }, completeness: { complete: true }, pagination: { offset: 0, limit: 100, total: 0, returned: 0, has_more: false } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}

const title = "AI agent can reach a credential or privileged tool through a configured MCP server";
for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`MCP evidence hierarchy ${theme} ${width}`, async ({ page }, info) => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    const nodes = [node("client", "agent", "Claude Desktop"), node("github-1", "server", "github"),
      node("github-2", "server", "github"), node("files-1", "server", "filesystem"), node("files-2", "server", "filesystem"),
      node("github-package", "package", "@modelcontextprotocol/server-github@2025.4.8"),
      node("files-package", "package", "@modelcontextprotocol/server-filesystem@2.0.1"),
      node("credential", "credential", "GITHUB_PERSONAL_ACCESS_TOKEN"), node("finding", "misconfiguration", title)];
    nodes.at(-1)!.severity = "high";
    nodes[0]!.attributes = { agent_type: "claude-desktop" };
    nodes[5]!.attributes = { ecosystem: "npm", version: "2025.4.8" };
    nodes[6]!.attributes = { ecosystem: "npm", version: "2.0.1" };
    const edges = [edge("client", "github-1", "uses"), edge("client", "files-1", "uses"),
      edge("github-1", "github-package", "depends_on"), edge("github-2", "github-package", "depends_on"),
      edge("files-1", "files-package", "depends_on"), edge("files-2", "files-package", "depends_on"),
      edge("github-1", "credential", "exposes_cred"), edge("credential", "finding", "exposed_to"), edge("client", "finding", "exposed_to")];
    edges[7]!.evidence.tier = "derived";
    edges[8]!.evidence.tier = "derived";
    await fixture(page, nodes, edges);
    await page.goto("/security-graph?lens=estate&scan=snapshot&rollup=0&layers=agent,server,package,credential,misconfiguration");
    if (width === 390) {
      await expect(page.getByRole("group", { name: "Investigation view" })).toBeVisible();
      await expect(page.getByText(title, { exact: true }).first()).toBeVisible();
      await expect(page.getByTestId("graph-path-list").getByText("Client link not recorded", { exact: true })).toHaveCount(2);
      await page.screenshot({ path: info.outputPath(`mcp-list-${theme}-${width}.png`), fullPage: width === 390 });
      await page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true }).click();
    }
    await expect(page.locator("[data-evidence-flow]")).toHaveCount(9);
    await expect(page.locator("[data-evidence-flow] .graph-entity-glyph.rounded-full")).toHaveCount(9);
    await expect(page.locator("[data-evidence-column]")).toHaveCount(0);
    await page.locator(".react-flow").scrollIntoViewIfNeeded();
    await expect.poll(() => page.locator("[data-evidence-flow]").evaluateAll(cards => cards.every(card => {
      const r = card.getBoundingClientRect(); return r.width > 0 && r.height > 0;
    }))).toBe(true);
    await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
    if (width === 1440) {
      await expect.poll(() => page.locator(".react-flow").evaluate(canvas => {
        const box = canvas.getBoundingClientRect();
        return [...canvas.querySelectorAll("[data-evidence-flow]")].every(node => {
          const r = node.getBoundingClientRect();
          return r.left >= box.left && r.right <= box.right && r.top >= box.top && r.bottom <= box.bottom;
        });
      })).toBe(true);
      const titles = await page.locator("[data-evidence-flow] > p").evaluateAll(items => items.map(item => ({
        label: item.textContent, clipped: item.scrollHeight > item.clientHeight + 1,
      })));
      expect(titles.filter(item => item.clipped)).toEqual([]);
      const xs = await page.locator('.react-flow__node').evaluateAll(items => Object.fromEntries(items.map(item => [item.getAttribute("data-id"), item.getBoundingClientRect().x])));
      expect(Math.abs(xs["github-1"] - xs["github-2"])).toBeLessThan(1);
      expect(xs.client).toBeLessThan(xs["github-2"]);
      const crossings = await page.locator(".react-flow").evaluate((canvas, links) => {
        const cards = [...canvas.querySelectorAll<HTMLElement>(".react-flow__node")].map(card => ({ id: card.dataset.id, box: card.getBoundingClientRect() }));
        return [...canvas.querySelectorAll<SVGPathElement>(".react-flow__edge-path")].flatMap(path => {
          const id = path.closest(".react-flow__edge")?.getAttribute("data-id");
          const link = links.find(e => e.id === id), matrix = path.getScreenCTM();
          if (!link || !matrix) return [];
          for (let at = 1; at < path.getTotalLength(); at += 3) {
            const p = path.getPointAtLength(at).matrixTransform(matrix);
            if (cards.some(card => card.id !== link.source && card.id !== link.target && p.x > card.box.left + 2 && p.x < card.box.right - 2 && p.y > card.box.top + 2 && p.y < card.box.bottom - 2)) return [id];
          }
          return [];
        });
      }, edges);
      expect(crossings).toEqual([]);
    }
    if (width === 1440) {
      await page.locator('.react-flow__node[data-id="client"]').hover();
      await page.mouse.move(0, 0);
      let stable = 0, prior = "";
      await expect.poll(async () => {
        const state = await page.locator(".react-flow").evaluate(canvas => {
          const box = canvas.getBoundingClientRect();
          return { transform: canvas.querySelector<HTMLElement>(".react-flow__viewport")?.style.transform,
            fits: [...canvas.querySelectorAll("[data-evidence-flow]")].every(node => {
              const r = node.getBoundingClientRect();
              return r.left >= box.left && r.right <= box.right && r.top >= box.top && r.bottom <= box.bottom;
            }) };
        });
        const next = state.transform ?? "";
        stable = state.fits && next === prior ? stable + 1 : 0;
        prior = next;
        return stable;
      }, { intervals: [100], timeout: 8000 }).toBeGreaterThanOrEqual(8);
    }
    if (width === 390) {
      const navigation = page.getByRole("group", { name: "Navigate loaded graph nodes" });
      await expect(navigation).toBeVisible();
      await navigation.getByRole("button", { name: "Next graph node" }).click();
      await expect(navigation).toContainText("Canvas target · 2 of 9");
      await navigation.getByRole("button", { name: "Previous graph node" }).click();
      await expect(navigation).toContainText("Canvas target · 1 of 9");
    }
    await page.screenshot({ path: info.outputPath(`mcp-flow-${theme}-${width}.png`), fullPage: width === 390 });
    await page.locator('.react-flow__node[data-id="finding"]').click();
    await expect(page.locator('.react-flow__node[data-id="github-1"]')).not.toHaveClass(/lineage-node-dim/);
    await expect(page.locator('.react-flow__node[data-id="files-2"]')).toHaveClass(/lineage-node-dim/);
    await expect(page.getByTestId("graph-entity-drawer")).toContainText(title);
    if (width === 390) {
      await expect.poll(() => page.getByTestId("graph-entity-drawer").getByRole("dialog").evaluate(dialog => getComputedStyle(dialog).opacity)).toBe("1");
    }
    await page.screenshot({ path: info.outputPath(`mcp-selected-${theme}-${width}.png`), fullPage: width === 390 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  });
}


test("IaC subtype URL filters the rendered graph without changing canonical entity types", async ({ page }) => {
  const nodes = [node("iac", "misconfiguration", "Privileged container"), node("other", "misconfiguration", "Other finding"), node("resource", "resource", "Container")];
  nodes[0]!.attributes = { finding_kind: "iac" };
  await fixture(page, nodes, [edge("iac", "resource", "affects"), edge("other", "resource", "affects")]);
  await page.goto("/security-graph?lens=estate&scan=snapshot&rollup=0&layers=cloudResource,misconfiguration&findingKind=iac");
  await expect(page.locator('.react-flow__node[data-id="iac"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="resource"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="other"]')).toHaveCount(0);
  await expect(page.locator('.react-flow__node[data-id="iac"]')).toContainText("IaC finding");
});


for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`mixed endpoint and MCP findings ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height:1000 });
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme",t),theme);
    const nodes = [node("endpoint","api_gateway","Public application endpoint"), node("instance","cloud_resource","checkout-worker"),
      node("mcp","server","Warehouse MCP"), node("role","role","Warehouse reader"), node("data","data_store","Customer records"),
      node("cve-1","vulnerability","CVE-2026-1000"), node("cve-2","vulnerability","CVE-2026-2000"), node("config","misconfiguration","Server allows unreviewed tools")];
    nodes[1]!.attributes = { resource_type:"ec2_instance", cloud_provider:"aws" };
    nodes[5]!.severity="critical"; nodes[6]!.severity="high"; nodes[7]!.severity="medium";
    const edges = [edge("endpoint","instance","exposed_to"),edge("instance","mcp","hosts"),edge("mcp","role","authenticates_as"),edge("role","data","has_permission"),
      edge("mcp","cve-1","vulnerable_to"),edge("mcp","cve-2","vulnerable_to"),edge("config","mcp","affects")];
    await fixture(page,nodes,edges);
    await page.goto("/security-graph?lens=estate&scan=snapshot&rollup=0&layers=apiGateway,cloudResource,server,role,dataStore,vulnerability,misconfiguration");
    if (width === 390) await page.getByRole("group", { name:"Investigation view" }).getByRole("button", { name:"Graph", exact:true }).click();
    await expect(page.locator('.react-flow__node')).toHaveCount(5);
    await expect(page.locator('[data-evidence-flow]')).toHaveCount(5);
    await expect(page.getByRole("button", { name:"Expand 3 findings for Warehouse MCP" })).toBeVisible();
    await expect(page.locator('[data-graph-adaptive-frame]')).toHaveAttribute("data-graph-camera-settled","true");
    await page.locator('.react-flow').scrollIntoViewIfNeeded();
    await page.screenshot({ path:info.outputPath(`mixed-collapsed-${theme}-${width}.png`),fullPage:true });
    // The toolbar remains available when the owner is outside a phone's focused viewport.
    await page.getByRole("button", { name:"Expand findings (3 grouped)",exact:true }).click();
    await expect(page.locator('.react-flow__node')).toHaveCount(8);
    await expect(page.locator('.react-flow__node[data-id="cve-1"]')).toContainText("CVE-2026-1000");
    await expect(page.locator('.react-flow__edge[data-id="config:affects:mcp"]')).toHaveCount(1);
    await expect(page.locator('[data-graph-adaptive-frame]')).toHaveAttribute("data-graph-camera-settled","true");
    if (width === 1440) {
      await expect.poll(() => page.locator(".react-flow").evaluate(canvas => {
        const marks = [...canvas.querySelectorAll(".graph-provider-mark-node")].map(mark => mark.getBoundingClientRect());
        return [...canvas.querySelectorAll<SVGPathElement>(".react-flow__edge-path")].filter(path => {
          const matrix = path.getScreenCTM();
          if (!matrix) return false;
          for (let at=0; at<path.getTotalLength(); at+=2) {
            const p=path.getPointAtLength(at).matrixTransform(matrix);
            if (marks.some(box => p.x>box.left && p.x<box.right && p.y>box.top && p.y<box.bottom)) return true;
          }
          return false;
        }).length;
      })).toBe(0);
    }
    await page.screenshot({ path:info.outputPath(`mixed-expanded-${theme}-${width}.png`),fullPage:true });
    await page.getByRole("button", { name:"Collapse findings",exact:true }).click();
    await expect(page.locator('.react-flow__node')).toHaveCount(5);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth+1)).toBe(true);
  });
}
