import { test, expect, type Page } from "@playwright/test";

const stamp = "2026-10-15T00:00:00Z";
const estate = "current-estate:0123456789abcdef0123456789abcdef";
const node = (id: string, label: string, entity_type: string) => ({
  id, label, entity_type, severity: "high", status: "active", risk_score: 0, attributes: {}, dimensions: {}, data_sources: ["fixture"], compliance_tags: [],
});
const nodes = [
  node("agent:planner", "planner", "agent"),
  node("server:fs", "filesystem", "server"),
  node("package:new", "requests@2.32.0", "package"),
  node("package:kept", "pydantic@2.8.0", "package"),
  node("server:image", "nginx", "server"),
  node("package:image", "openssl@3.0.2", "package"),
  node("package:image-2", "zlib@1.3", "package"),
];
const edge = (source: string, target: string, relationship: string) => ({
  id: `${source}->${target}`, source, target, relationship, direction: "directed", weight: 1, traversable: true,
  evidence: { tier: "static_scan", source: "fixture" }, first_seen: stamp, last_seen: stamp,
});
const edges = [
  edge("agent:planner", "server:fs", "uses"), edge("server:fs", "package:new", "depends_on"), edge("server:fs", "package:kept", "depends_on"),
  edge("server:image", "package:image", "depends_on"), edge("server:image", "package:image-2", "depends_on"),
];
const graph = {
  scan_id: estate, tenant_id: "fixture", created_at: stamp, evidence_scope: "current_estate", nodes, edges, attack_paths: [], interaction_risks: [],
  stats: { total_nodes: nodes.length, total_edges: edges.length, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 },
};
const ref = (scan: string, at: string) => ({ scan_id: scan, job_id: scan, captured_at: at });
const changes = {
  schema_version: "v1", evidence_scope: "current_estate",
  sources: [
    { scope_id: "a1b2", label: "repo github.com/acme/agents", old: ref("repo-1", "2026-10-08T09:00:00+00:00"), new: ref("repo-2", "2026-10-15T09:00:00+00:00"),
      counts: { nodes: { added: 1, removed: 1, changed: 0 }, edges: { added: 1, removed: 1, changed: 0 } }, total_changes: 4, nodes_by_entity_type: {}, highlights: {}, skipped_snapshots: 0 },
    { scope_id: "c3d4", label: "aws / 123456789012 / us-east-1", old: ref("aws-1", "2026-10-09T09:00:00+00:00"), new: ref("aws-2", "2026-10-15T08:00:00+00:00"),
      counts: { nodes: { added: 0, removed: 0, changed: 0 }, edges: { added: 0, removed: 0, changed: 0 } }, total_changes: 0, nodes_by_entity_type: {}, highlights: {}, skipped_snapshots: 0 },
  ],
  new_sources: [{ scope_id: "e5f6", label: "image nginx:1.27", new: ref("image-1", "2026-10-14T12:00:00+00:00"), reason: "first_observation", node_count: 3, edge_count: 2, skipped_snapshots: 0 }],
  totals: { nodes: { added: 1, removed: 1, changed: 0 }, edges: { added: 1, removed: 1, changed: 0 }, changed_sources: 1, unchanged_sources: 1, new_sources: 1 },
  pagination: { offset: 0, limit: 50, returned: 3, total: 3, has_more: false, next_offset: null },
  completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 3, total: 3 },
  completeness_reasons: [],
};
const repoDiff = {
  schema_version: "v1", old: "repo-1", new: "repo-2", view: "full",
  nodes_added: [{ id: "package:new", label: "requests@2.32.0", entity_type: "package" }], nodes_removed: [{ id: "package:old", label: "urllib3@1.26", entity_type: "package" }],
  nodes_changed: [], edges_added: [["server:fs", "package:new", "depends_on"]], edges_removed: [["server:fs", "package:old", "depends_on"]],
  change_kind_index: { nodes: { "package:new": "new", "package:old": "removed" }, edges: { "server:fs|package:new|depends_on": "new" } },
  summary: { totals: { nodes: { added: 1, removed: 1, changed: 0 }, edges: { added: 1, removed: 1, changed: 0 } } },
  truncated: false, total_changes: 4, returned_changes: 4,
};

async function fixture(page: Page, changesBody: unknown = changes) {
  const requests: string[] = [];
  await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", r => {
    const u = new URL(r.request().url());
    requests.push(u.pathname + u.search);
    if (u.pathname === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (u.pathname === "/v1/inventory/summary") return r.fulfill({ json: { scan_id: estate, tenant_id: "fixture", total_assets: nodes.length, evidence_scope: "current_estate", snapshot_generation: "0123" } });
    if (u.pathname === "/v1/graph/snapshots") return r.fulfill({ json: ["repo-2", "aws-2", "image-1", "repo-1", "aws-1"].map(scan_id => ({ scan_id, created_at: stamp, node_count: 3, edge_count: 2 })) });
    if (u.pathname === "/v1/graph") return r.fulfill({ json: { ...graph, pagination: { total: nodes.length, offset: 0, limit: 100, returned: nodes.length, has_more: false } } });
    if (u.pathname === "/v1/graph/changes") return r.fulfill({ json: changesBody });
    if (u.pathname === "/v1/graph/diff") return r.fulfill({ json: repoDiff });
    if (u.pathname === "/v1/graph/edges/changes") return r.fulfill({ json: { scan_id_old: "repo-1", scan_id_new: "repo-2", edges_added: [], edges_removed: [], edges_changed: [], edges_unchanged: [], summary: { added: 0, removed: 0, changed: 0, unchanged: 0 } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
  return requests;
}

for (const [theme, width] of [["light", 1440], ["dark", 1440], ["light", 390], ["dark", 390]] as const) {
  test(`estate changes entry, panel, highlight and per-source diff ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: width > 600 ? 1000 : 844 });
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    const requests = await fixture(page);
    await page.goto("/graph?rollup=0");
    const entry = page.getByTestId("graph-changes-entry");
    await expect(entry).toContainText("+1 −1 nodes · +1 −1 links · 1 source · 1 first observation");
    expect(requests.filter(p => p.startsWith("/v1/graph/changes")).length).toBe(1);
    expect(requests.filter(p => p.startsWith("/v1/graph/diff"))).toEqual([]);
    await entry.scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath(`changes-entry-${theme}-${width}.png`), animations: "disabled" });

    await entry.getByRole("button", { name: /changed since previous scans/i }).click();
    const panel = page.getByRole("dialog", { name: "Changed since previous scans" });
    await expect(panel).toBeVisible();
    const sources = panel.getByTestId("graph-changes-source");
    await expect(sources).toHaveCount(2);
    await expect(sources.nth(0)).toContainText("repo github.com/acme/agents");
    await expect(sources.nth(0)).toContainText("+1 −1 nodes · +1 −1 links");
    await expect(sources.nth(1)).toContainText("No changes");
    await expect(panel.getByTestId("graph-changes-first-observation")).toContainText("image nginx:1.27");
    await expect(panel.getByTestId("graph-changes-first-observation")).toContainText("not counted as additions");
    await page.screenshot({ path: info.outputPath(`changes-panel-${theme}-${width}.png`), animations: "disabled" });

    await sources.nth(0).getByRole("button", { name: /open diff/i }).click();
    await expect(sources.nth(0).getByTestId("graph-snapshot-diff")).toContainText("requests@2.32.0");
    await page.screenshot({ path: info.outputPath(`changes-diff-${theme}-${width}.png`), animations: "disabled" });
    await expect.poll(() => requests.filter(p => p.startsWith("/v1/graph/diff?") && p.includes("old=repo-1") && p.includes("new=repo-2")).length).toBeGreaterThan(0);

    await panel.getByRole("button", { name: "Highlight changes" }).click();
    await expect(panel).toBeHidden();
    await expect(page.locator('.react-flow__node[data-id="package:new"]')).toHaveClass(/drift-ring-new/);
    await expect(page.locator('.react-flow__node[data-id="package:kept"]')).not.toHaveClass(/drift-ring-new/);
    await expect(entry.getByRole("button", { name: /clear highlight/i })).toBeVisible();
    await page.screenshot({ path: info.outputPath(`changes-highlight-${theme}-${width}.png`), animations: "disabled" });
    await entry.getByRole("button", { name: /clear highlight/i }).click();
    await expect(page.locator('.react-flow__node[data-id="package:new"]')).not.toHaveClass(/drift-ring-new/);
  });
}

test("a source scanned once compares with the declared baseline and drills into new exposure", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  const baselined = {
    ...changes,
    sources: [{
      scope_id: "f7f8", label: "local-agents", old: { scan_id: "showcase-baseline", job_id: "", captured_at: "2026-10-08T02:00:00+00:00" },
      new: ref("repo-2", "2026-10-15T02:00:00+00:00"), baseline: "snapshot_continuity",
      counts: { nodes: { added: 1, removed: 1, changed: 0 }, edges: { added: 1, removed: 1, changed: 0 } }, total_changes: 4, nodes_by_entity_type: {}, skipped_snapshots: 0,
      issue_change: { basis: "issue_groups", old: { critical: 4, high: 9, medium: 0, low: 0, total: 13 }, new: { critical: 5, high: 9, medium: 0, low: 0, total: 14 } },
      highlights: {
        new_critical_findings: { count: 1, top: [{ kind: "node", change: "added", id: "package:new", label: "requests@2.32.0", severity: "critical", entity_type: "package" }] },
        new_attack_paths: { status: "complete", count: 1, top: [{ source: "agent:planner", target: "package:new", hops: ["agent:planner", "server:fs", "package:new"], composite_risk: 71, summary: "" }] },
        removed_attack_paths: { status: "complete", count: 7, top: Array.from({ length: 7 }, (_, i) => (
          { source: `agent:old-${i}`, target: "package:old", hops: [`agent:old-${i}`, "package:old"], composite_risk: 60 - i, summary: "" }
        )) },
      },
    }],
    new_sources: [], completeness_reasons: ["snapshot_baseline"],
    totals: { ...changes.totals, changed_sources: 1, unchanged_sources: 0, new_sources: 0 },
  };
  const requests = await fixture(page, baselined);
  await page.goto("/graph?rollup=0");
  const entry = page.getByTestId("graph-changes-entry");
  await expect(entry).toContainText("+1 −1 nodes · +1 −1 links · 1 source");
  await expect(entry).not.toContainText("First observation");
  await entry.getByRole("button", { name: /changed since previous scans/i }).click();
  const panel = page.getByRole("dialog", { name: "Changed since previous scans" });
  await expect(panel.getByTestId("graph-changes-source")).toContainText("Compared with earlier snapshot showcase-baseline");
  await expect(panel.getByTestId("graph-changes-first-observation")).toHaveCount(0);
  const exposure = panel.getByTestId("graph-changes-exposure");
  await expect(exposure).toContainText("New critical finding nodes · 1");
  await expect(exposure).toContainText("New attack paths · 1");
  await expect(panel.getByTestId("graph-changes-issue-basis")).toHaveText("Open issues, the posture trend's unit: critical 4 → 5 (+1) · high 9 → 9 (no change)");
  const removed = exposure.getByRole("group", { name: "Removed attack paths" });
  await expect(removed).toContainText("1–5 of 7");
  await removed.getByRole("button", { name: "Next removed attack paths page" }).focus();
  await page.keyboard.press("Enter");
  await expect(removed).toContainText("6–7 of 7");
  const removedLink = removed.getByRole("link", { name: "Open removed path agent:old-6 → package:old in the previous snapshot" });
  const removedHref = new URL((await removedLink.getAttribute("href"))!, "http://x");
  expect(removedHref.pathname).toBe("/security-graph");
  expect(removedHref.searchParams.get("scan")).toBe("showcase-baseline");
  await exposure.getByRole("button", { name: "Investigate requests@2.32.0" }).click();
  await expect(panel).toBeHidden();
  await expect.poll(() => requests.some(p => p.startsWith("/v1/graph/query"))).toBe(true);
});
