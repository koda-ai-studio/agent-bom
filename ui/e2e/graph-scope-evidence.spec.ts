import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import fixture from "../tests/fixtures/product-proof-rollup.json";
const graphFixture = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e",
  'import { buildGraph } from "./scripts/product-proof-graph.mjs"; import { graphImpact } from "./scripts/static-demo-routes.mjs"; const graph=buildGraph(); process.stdout.write(JSON.stringify({ graph, impacts: Object.fromEntries(graph.nodes.map(node => [node.id, graphImpact(graph,node.id)])) }));'], { encoding: "utf8" }));

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`agent scope exposes direction, shared MCP and exact findings ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
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
    await page.goto(`/graph?scan=${graph.scan_id}&rollup=1`);
    const canvas = page.getByTestId("graph-agent-evidence");
    await expect(canvas).toBeVisible();
    if (width === 1440) {
      await expect(canvas.locator('.react-flow__node[data-id="server:filesystem"]')).toBeVisible();
      const roleLink = canvas.locator('.react-flow__edge').filter({ has: page.locator('[data-relationship="can_access"]') });
      await expect(roleLink.locator(".react-flow__edge-path")).toHaveAttribute("marker-end", /.+/);
      await expect(canvas.locator('[data-relationship="shares_server"]')).toHaveCount(0);
      await expect(canvas.locator("[data-internet-anchor]")).toHaveCount(0);
      await expect(canvas.locator(".react-flow__node")).toHaveCount(6);
      await expect(canvas.locator(".graph-relationship-label:visible")).toHaveCount(5);
      await expect(roleLink).toBeVisible();
      await expect(canvas.locator(".graph-relationship-label").filter({ hasText: "Can Access" })).toContainText("modeled");
    } else {
      await expect(canvas.locator("li[data-recorded-edge]")).toHaveCount(5);
      await expect(canvas.locator("li").filter({ hasText: "prod-ai-admin" })).toContainText("prod-ai-admin→Developer Copilot");
      await expect(canvas.locator("li").filter({ hasText: "prod-ai-admin" })).toContainText("Modeled");
      await expect(canvas.locator("li").filter({ hasText: "SRE Runbook Agent" })).toContainText("filesystem MCP");
    }
    await page.waitForLoadState("networkidle");
    await page.screenshot({ path: info.outputPath(`agent-first-${theme}-${width}.png`), fullPage: true });
    if (width === 1440) {
      await page.getByText(/Relationship evidence \(/).click();
      await expect(page.getByText(/prod-ai-admin → Developer Copilot · can access/)).toBeVisible();
      await expect(page.getByText(/SRE Runbook Agent → filesystem MCP · uses/)).toBeVisible();
      await canvas.getByRole("button", { name: "Inspect 1 finding in the scope of Developer Copilot" }).click();
    } else await canvas.getByRole("button", { name: "Open 1 finding for Developer Copilot" }).click();
    const findings = page.getByRole("region", { name: "Findings for Developer Copilot" });
    await expect(findings).toContainText("1 open issue");
    await expect(findings).toContainText("CVE-2024-37891");
    await expect(findings.getByRole("button", { name: "Inspect evidence" })).toBeVisible();
    await page.screenshot({ path: info.outputPath(`agent-findings-${theme}-${width}.png`), fullPage: true });
    await findings.getByRole("button", { name: "Close findings" }).click();
    if (width === 1440) await canvas.locator('.react-flow__node[data-id="server:filesystem"]').click();
    else await canvas.getByRole("button", { name: "filesystem MCP", exact: true }).first().click();
    await expect.poll(() => queries.at(-1)?.roots).toEqual(["server:filesystem"]);
    await expect(page.getByText("execute_command", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("AWS_ROLE_SESSION", { exact: true }).first()).toBeVisible();
    await page.screenshot({ path: info.outputPath(`server-expanded-${theme}-${width}.png`), fullPage: true });
    expect(errors).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
