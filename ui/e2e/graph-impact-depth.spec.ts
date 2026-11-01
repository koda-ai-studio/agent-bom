import { expect, test } from "@playwright/test";

// The API's real traversal is covered by test_graph_impact_default_depth.py.
// This journey verifies that the browser does not replace that scope with four hops.
const identity = { scan_id: "long-path", tenant_id: "fixture", snapshot_generation: "a".repeat(32) };
const stamp = "2026-10-18T00:00:00Z";
const nodes = [
  ["agent:far", "agent"], ["server:etl", "server"], ["container:workload", "container"],
  ["container:image", "container"], ["package:pillow", "package"], ["finding:cve", "vulnerability"],
].map(([id, entity_type]) => ({ id: id!, entity_type: entity_type!, label: id!, attributes: {}, dimensions: {},
  status: "active", severity: "high", risk_score: 0, data_sources: ["fixture"], compliance_tags: [] }));
const root = nodes.at(-1)!;
const edges = nodes.slice(0, -1).map((node, i) => ({ id: `edge:${i}`, source: node.id, target: nodes[i + 1]!.id,
  relationship: i === 4 ? "vulnerable_to" : "depends_on", direction: "directed", weight: 1, traversable: true,
  evidence: { tier: "static_scan", source: "fixture" }, first_seen: stamp, last_seen: stamp }));

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`blast radius retains a five-hop source ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const impactDepths: (string | null)[] = [];
    const queries: { max_depth: number; max_nodes: number }[] = [];
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: {
        authenticated: true, auth_required: false, tenant_id: identity.tenant_id, role: "admin", auth_method: "anonymous",
        memberships: [], configured_modes: [], recommended_ui_mode: "no_auth",
      } });
      if (url.pathname === "/v1/graph/snapshots") return route.fulfill({ json: [{ ...identity, created_at: stamp, node_count: 6, edge_count: 5 }] });
      if (url.pathname === "/v1/graph/query") {
        const body = route.request().postDataJSON(); queries.push(body);
        const selected = nodes.slice(-body.max_nodes);
        const ids = new Set(selected.map(node => node.id));
        return route.fulfill({ json: { ...identity, created_at: stamp, roots: [root.id], nodes: selected,
          edges: edges.filter(edge => ids.has(edge.source) && ids.has(edge.target)), attack_paths: [], interaction_risks: [],
          depth_by_node: Object.fromEntries(selected.map(node => [node.id, nodes.length - 1 - nodes.indexOf(node)])),
          truncated: true, direction: "reverse", max_depth: body.max_depth,
          stats: { total_nodes: selected.length, total_edges: selected.length - 1, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 },
          budget: {}, completeness: { complete: false },
        } });
      }
      if (url.pathname === "/v1/graph/impact") {
        impactDepths.push(url.searchParams.get("max_depth"));
        const depth = Number(url.searchParams.get("max_depth") ?? 5);
        const affected = nodes.slice(Math.max(0, nodes.length - 1 - depth), -1);
        return route.fulfill({ json: { ...identity, node_id: root.id, affected_nodes: affected.map(node => node.id),
          affected_count: affected.length, affected_by_type: { agent: 1, server: 1, container: 2, package: 1 },
          max_depth: depth, max_depth_reached: depth, depth_basis: "longest_materialized_path", completeness: { complete: true },
        } });
      }
      if (url.pathname.startsWith("/v1/graph/node/")) return route.fulfill({ json: {
        ...identity, node: root, sources: [], neighbors: [], edges_in: [edges.at(-1)], edges_out: [], completeness: { complete: true },
        impact: { affected_count: 5, affected_by_type: { agent: 1, server: 1, container: 2, package: 1 }, max_depth_reached: 5 },
      } });
      return route.fulfill({ status: 404, json: { detail: "No fixture response" } });
    });
    await page.goto(`/graph?scan=${identity.scan_id}&root=${encodeURIComponent(root.id)}`);
    await page.getByRole("button", { name: "Show blast radius", exact: true }).click();
    await expect(page.getByText(`5 upstream related nodes connected to ${root.label}`, { exact: true })).toBeVisible();
    expect(impactDepths).toEqual([null]);
    expect(queries.at(-1)).toMatchObject({ max_depth: 5, max_nodes: 4 });
    await expect(page.getByText(/3 related nodes shown on this bounded map/)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: info.outputPath(`long-path-impact-${theme}-${width}.png`), fullPage: true });
  });
}
