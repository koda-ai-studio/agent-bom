import { test, expect, type Page } from "@playwright/test";
const stamp = "2026-10-15T00:00:00Z";
const nodes = [
  { id: "package:demo", label: "pillow@9.0.0", entity_type: "package", attributes: { version: "9.0.0" } },
  { id: "vuln:demo", label: "CVE-2023-4863", entity_type: "vulnerability", attributes: { fixed_version: "10.0.1" } },
].map(n => ({ ...n, severity: "high", status: "active", risk_score: 0, dimensions: {}, data_sources: ["fixture"], compliance_tags: [] }));
const edge = { id: "finding", source: nodes[0]!.id, target: nodes[1]!.id, relationship: "vulnerable_to", direction: "directed", weight: 1, traversable: true, evidence: {tier: "static_scan", source: "fixture"}, first_seen: stamp, last_seen: stamp };
const graph = { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, nodes, edges: [edge], attack_paths: [], interaction_risks: [], stats: { total_nodes: 2, total_edges: 1, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 } };
async function fixture(page: Page, topology = graph) {
  const requests: string[] = [];
  await page.route("**/health", r => r.fulfill({ json: {status: "ok"} }));
  await page.route("**/v1/**", r => {
    const u = new URL(r.request().url()); requests.push(u.pathname+u.search);
    if (u.pathname === "/v1/auth/me") return r.fulfill({json: {authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth"}});
    if (u.pathname === "/v1/graph/snapshots") return r.fulfill({json: ["snapshot", "previous"].map(scan_id=>({scan_id,created_at:stamp,node_count:topology.nodes.length,edge_count:topology.edges.length}))});
    if (u.pathname === "/v1/graph") return r.fulfill({json: {...topology,pagination:{total:topology.nodes.length,offset:0,limit:100,returned:topology.nodes.length,has_more:false}}});
    if (u.pathname === "/v1/graph/query") return r.fulfill({json: {...topology,roots:[nodes[1]!.id],depth_by_node:{[nodes[0]!.id]:1,[nodes[1]!.id]:0},truncated:false,direction:"reverse",max_depth:1,budget:{}}});
    if (u.pathname.startsWith("/v1/graph/node/")) return r.fulfill({json: {node:nodes[1],sources:[],edges_in:[edge],edges_out:[],neighbors:[nodes[0]!.id],impact:{affected_count:1,max_depth_reached:1,affected_by_type:{package:1}},completeness:{complete:true}}});
    if (u.pathname === "/v1/graph/diff") return r.fulfill({json:{nodes_added:[],nodes_removed:[],nodes_changed:[],edges_added:[],edges_removed:[]}});
    if (u.pathname === "/v1/graph/edges/changes") return r.fulfill({json:{scan_id_old:"previous",scan_id_new:"snapshot",edges_added:[],edges_removed:[],edges_changed:[],edges_unchanged:[],summary:{added:0,removed:0,changed:0,unchanged:0}}});
    if (u.pathname === "/v1/graph/rollup") return r.fulfill({json: {...graph, mode:u.searchParams.has("node")?"drilldown":"rollup",node:u.searchParams.has("node")?{id:u.searchParams.get("node"),label:"Pinned scope"}:null,top_level:[],children:[],summary:{total_nodes:2},completeness:{complete:true},pagination:{offset:0,limit:100,total:0,returned:0,has_more:false}}});
    return r.fulfill({status:404,json:{detail:"Outside fixture"}});
  });
  return requests;
}
for (const theme of ["light", "dark"]) test(`small graph uses its canvas and defers comparison ${theme}`, async({page},info)=>{
  await page.setViewportSize({width:1440,height:1000});
  await page.addInitScript(t=>localStorage.setItem("agent-bom-theme",t),theme);
  const requests=await fixture(page);
  await page.goto("/graph?scan=snapshot&root=vuln%3Ademo&lens=context");
  await expect(page.locator(".react-flow__node")).toHaveCount(2);
  await expect(page.getByTestId("graph-entity-drawer").getByRole("heading",{name:"CVE-2023-4863",exact:true})).toBeVisible();
  await expect.poll(async()=>Math.round((await page.locator(".react-flow").boundingBox())!.height)).toBeLessThanOrEqual(560);
  await expect.poll(async()=>{
    const canvas=(await page.locator(".react-flow").boundingBox())!;
    const glyphs=await page.locator(".react-flow .graph-entity-glyph").evaluateAll(es=>es.map(e=>e.getBoundingClientRect().toJSON()));
    return glyphs.length===2 && glyphs.every(g=>g.width>=65 && g.x>=canvas.x && g.right<=canvas.x+canvas.width && g.y>=canvas.y && g.bottom<=canvas.y+canvas.height);
  }).toBe(true);
  expect(requests.filter(p=>p.startsWith("/v1/graph/diff?")||p.startsWith("/v1/graph/edges/changes?"))).toEqual([]);
  expect(requests.filter(p=>p.startsWith("/v1/graph/node/"))).toHaveLength(1);
  await page.screenshot({path:info.outputPath(`compact-${theme}.png`),animations:"disabled"});
  const transform = await page.locator(".react-flow__viewport").getAttribute("style");
  await page.locator('.react-flow__node[data-id="package:demo"]').hover();
  await expect(page.locator(".react-flow__viewport")).toHaveAttribute("style", transform!);
  await page.getByRole("button", { name: "View & layers" }).click();
  await page.locator("summary").filter({ hasText: "Advanced controls" }).click();
  await page.locator("summary").filter({ hasText: /^Snapshot diff/ }).click();
  await expect.poll(() => requests.filter(p => p.startsWith("/v1/graph/diff?")).length).toBe(1);
  await expect.poll(() => requests.filter(p => p.startsWith("/v1/graph/edges/changes?")).length).toBe(1);
});
test("a saved scope link opens that scope instead of returning to the estate",async({page})=>{
 const requests=await fixture(page);
 await page.goto("/graph?scan=snapshot&rollup=1&rollup_node=server%3Apinned");
 await expect.poll(()=>requests.filter(p=>p.startsWith("/v1/graph/rollup?")&&p.includes("node=server%3Apinned")).length).toBeGreaterThan(0);
 await expect(page).toHaveURL(/rollup_node=server%3Apinned/);
});

for (const theme of ["light", "dark"]) test(`three evidence sources stay readable ${theme}`, async ({ page }, info) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  const sources = ["pinned-package.txt", "image inventory", "deployment occurrence"].map((label, index) => ({
    ...nodes[0]!, id: `source:${index}`, label, entity_type: index === 0 ? "source_file" : "container", severity: "none",
  }));
  const topology = { ...graph, stats: { ...graph.stats, total_nodes: 5, total_edges: 4 }, nodes: [...sources, ...nodes], edges: [edge, ...sources.map(source => ({
    ...edge, id: source.id, source: source.id, target: nodes[0]!.id, relationship: "contains",
  }))] };
  await fixture(page, topology);
  await page.goto("/graph?scan=snapshot&rollup=0&layers=sourceFile,container,package,vulnerability");
  await expect(page.locator(".react-flow__node")).toHaveCount(5);
  await page.locator('.react-flow__node[data-id="vuln:demo"]').click();
  await expect(page.getByTestId("graph-entity-drawer")).toBeVisible();
  await expect.poll(async () => page.locator(".react-flow .graph-entity-glyph").evaluateAll(es => Math.min(...es.map(e => e.getBoundingClientRect().width))))
    .toBeGreaterThanOrEqual(50);
  const before = (await page.locator(".react-flow").boundingBox())!;
  await page.screenshot({ path: info.outputPath(`evidence-${theme}.png`), animations: "disabled" });
  await page.setViewportSize({ width: 1680, height: 900 });
  await expect.poll(async () => (await page.locator(".react-flow").boundingBox())!.width).toBeGreaterThan(before.width);
  await expect.poll(async () => {
    const canvas = (await page.locator(".react-flow").boundingBox())!;
    return canvas.y + canvas.height <= 900;
  }).toBe(true);
  await page.screenshot({ path: info.outputPath(`evidence-resized-${theme}.png`), animations: "disabled" });
  await page.getByRole("button", { name: "View & layers" }).click();
  await expect.poll(async () => (await page.locator(".react-flow").boundingBox())!.height).toBeLessThanOrEqual(320);
  await page.getByRole("button", { name: "View & layers" }).click();
  await expect.poll(async () => (await page.locator(".react-flow").boundingBox())!.height).toBeGreaterThan(400);
});
