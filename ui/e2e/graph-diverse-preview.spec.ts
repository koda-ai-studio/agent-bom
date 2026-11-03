import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) {
  test(`representative preview keeps every ranked occurrence (${theme})`, async ({ page }, info) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const stamp = "2026-11-01T00:00:00Z";
    const node = (id: string, entity_type: string) => ({ id, entity_type, label: id, severity: "high", status: "active", risk_score: 0, attributes: {}, dimensions: {}, data_sources: ["synthetic-fixture"], compliance_tags: [] });
    const advisories = ["CVE-2026-1000", "CVE-2026-2000", "CVE-2026-3000"];
    const nodes = [node("client", "agent"), ...advisories.map(id => node(id, "vulnerability")), ...Array.from({ length: 14 }, (_, i) => node(`server-${i}`, "server"))];
    const paths = Array.from({ length: 14 }, (_, i) => {
      const advisory = advisories[i < 12 ? 0 : i-11]!;
      return { source: "client", target: advisory, hops: ["client", `server-${i}`, advisory], edges: ["uses", "vulnerable_to"],
        composite_risk: 90-i, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: [advisory], finding_ids: [`finding-${i}`] };
    });
    const edges = paths.flatMap(path => path.edges.map((relationship, index) => ({ id: `${path.hops[index]}:${relationship}:${path.hops[index+1]}`, source: path.hops[index], target: path.hops[index+1], relationship, direction: "directed", traversable: true, weight: 1, evidence: { tier: "static_scan", source: "synthetic-fixture" }, first_seen: stamp, last_seen: stamp })));
    const graph = { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, nodes, edges, attack_paths: paths, interaction_risks: [],
      stats: { total_nodes: nodes.length, total_edges: 28, severity_counts: {}, analysis_status: { attack_path_fusion: { status: "complete", reason_codes: [], observed: {} } } },
      pagination: { total: 14, offset: 0, limit: 100, returned: 14, has_more: false },
      count_metadata: { source: "persisted_graph_paths", snapshot_total: 14, total: 14, returned: 14 } };
    const limits: string[] = [];
    await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", r => {
      const u = new URL(r.request().url());
      if (u.pathname === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
      if (u.pathname === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "snapshot", created_at: stamp, snapshot_kind: "scan", node_count: nodes.length, edge_count: 28 }] });
      if (u.pathname === "/v1/graph/attack-paths") { limits.push(u.searchParams.get("limit") || ""); return r.fulfill({ json: graph }); }
      if (u.pathname === "/v1/graph/views/fix-first") return r.fulfill({ json: { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, cards: [], attack_campaigns: [],
        summary: { total_paths: 14, matched_paths: 14, returned_paths: 0, highest_risk: 90, covered_findings: 0, node_count: nodes.length, edge_count: edges.length }, focus: { cve: "", package: "", agent: "" } } });
      return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
    });
    await page.goto("/security-graph?lens=attack-path&scan=snapshot");
    await expect(page.locator("#investigation-queue")).toHaveAttribute("open", "");
    const queue = page.getByLabel("Attack path queue", { exact: true });
    await expect(queue.getByRole("button")).toHaveCount(10);
    // The action must be exposed without scrolling a nested queue footer.
    await expect(page.getByRole("button", { name: "Show all loaded paths in ranked order" })).toBeInViewport();
    await expect(queue.getByTestId("ranked-path-advisory").nth(1)).toHaveText(advisories[1]!);
    await expect(queue.getByTestId("ranked-path-advisory").nth(2)).toHaveText(advisories[2]!);
    await expect(queue.getByRole("button").nth(1)).toContainText("#13");
    await queue.getByRole("button").nth(1).click();
    await expect(queue.getByRole("button")).toHaveCount(10);
    await expect(queue.getByRole("button").nth(1)).toHaveAttribute("aria-pressed", "true");
    await page.screenshot({ path: info.outputPath(`representative-${theme}.png`), fullPage: true });
    await page.getByRole("button", { name: "Show all loaded paths in ranked order" }).click();
    await expect(queue.getByRole("button")).toHaveCount(14);
    await expect(queue.getByTestId("ranked-path-advisory").nth(11)).toHaveText(advisories[0]!);
    await expect(queue.getByTestId("ranked-path-advisory").nth(12)).toHaveText(advisories[1]!);
    expect(limits).toContain("100");
    await page.screenshot({ path: info.outputPath(`all-ranked-${theme}.png`), fullPage: true });
  });
}
