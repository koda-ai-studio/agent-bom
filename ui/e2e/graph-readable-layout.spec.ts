import { readFile } from "node:fs/promises";
import { test, expect, type Page } from "@playwright/test";
import { ownedFindingAggregates, routeNodeAggregates, withSemanticLayer } from "./helpers/graph-rollup-mocks";
import { graphGrammarViolations } from "./helpers/graph-grammar";

const stamp = "2026-10-15T00:00:00Z";
// Nodes as the API serves them: each carries the backend legend layer for its kind.
const node = (id: string, entity_type: string, label = id) => withSemanticLayer({
  id, entity_type, label, severity: "none", status: "active", risk_score: 0, attributes: {},
  dimensions: { environment: "prod" }, data_sources: ["synthetic-fixture"], compliance_tags: [],
});
const edge = (source: string, target: string, relationship: string) => ({
  id: `${source}:${relationship}:${target}`, source, target, relationship, direction: "directed", traversable: true, weight: 1,
  evidence: { tier: "static_scan", source: "synthetic-fixture" }, first_seen: stamp, last_seen: stamp,
});
type FixtureNode = ReturnType<typeof node>;
type FixtureEdge = ReturnType<typeof edge>;

async function fixture(page: Page, nodes: FixtureNode[], edges: FixtureEdge[], truncated = false, graphMetadata: Record<string, unknown> = {}) {
  const graph = { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, nodes, edges, attack_paths: [], interaction_risks: [],
    stats: { total_nodes: nodes.length, total_edges: edges.length, severity_counts: {} }, ...graphMetadata };
  await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", r => {
    const u = new URL(r.request().url());
    if (u.pathname === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (u.pathname === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "snapshot", created_at: stamp, snapshot_kind: "scan", node_count: nodes.length, edge_count: edges.length }] });
    if (u.pathname === "/v1/graph") return r.fulfill({ json: { ...graph, pagination: { total: nodes.length, offset: 0, limit: 100, returned: nodes.length, has_more: false } } });
    if (u.pathname === "/v1/graph/query") return r.fulfill({ json: { ...graph, roots: ["agent"], depth_by_node: { agent: 0 }, truncated, direction: "both", max_depth: 1, budget: {} } });
    if (u.pathname.startsWith("/v1/graph/node/")) {
      const id = decodeURIComponent(u.pathname.split("/").at(-1)!);
      return r.fulfill({ json: { node: nodes.find(n => n.id === id), sources: [], edges_in: edges.filter(e => e.target === id), edges_out: edges.filter(e => e.source === id), neighbors: [], impact: { node_id: id, affected_nodes: [], affected_by_type: {}, affected_count: 0, max_depth_reached: 0 }, completeness: { complete: true } } });
    }
    if (u.pathname === "/v1/graph/rollup") return r.fulfill({ json: { ...graph, mode: "rollup", top_level: [], children: [], summary: { total_nodes: nodes.length }, completeness: { complete: true }, pagination: { offset: 0, limit: 100, total: 0, returned: 0, has_more: false } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}

/** Wait until the viewport transform stops changing (layout and fit settled). */
async function settle(page: Page) {
  let previous = "";
  let stable = 0;
  await expect.poll(async () => {
    const current = await page.locator(".react-flow__viewport").evaluate(element => getComputedStyle(element).transform);
    stable = current === previous ? stable + 1 : 0;
    previous = current;
    return stable;
  }, { intervals: [100], timeout: 10_000 }).toBeGreaterThanOrEqual(4);
}

/** Edges that pass through a node card other than their own endpoints. */
async function edgesThroughNodes(page: Page) {
  return page.locator(".react-flow").evaluate(canvas => {
    const cards = [...canvas.querySelectorAll<HTMLElement>(".react-flow__node")].map(n => {
      const card = n.querySelector("[data-graph-entity]") ?? n;
      const parts = [card, ...card.children].map(child => child.getBoundingClientRect()).filter(r => r.width && r.height);
      return { id: n.getAttribute("data-id")!, left: Math.min(...parts.map(r => r.left)), right: Math.max(...parts.map(r => r.right)),
        top: Math.min(...parts.map(r => r.top)), bottom: Math.max(...parts.map(r => r.bottom)) };
    });
    const hits: string[] = [];
    const inside = (p: DOMPoint, c: typeof cards[number], margin = 0) => p.x > c.left - margin && p.x < c.right + margin && p.y > c.top - margin && p.y < c.bottom + margin;
    for (const group of canvas.querySelectorAll<SVGGElement>(".react-flow__edge")) {
      const id = group.getAttribute("data-id") ?? "";
      const path = group.querySelector<SVGPathElement>(".react-flow__edge-path");
      if (!path) continue;
      const matrix = path.getScreenCTM()!;
      // Endpoints are the cards that contain the path's first and last points.
      const start = path.getPointAtLength(0).matrixTransform(matrix);
      const end = path.getPointAtLength(path.getTotalLength()).matrixTransform(matrix);
      for (const card of cards) {
        if (inside(start, card, 8) || inside(end, card, 8)) continue;
        for (let d = 0; d <= path.getTotalLength(); d += 3) {
          const p = path.getPointAtLength(d).matrixTransform(matrix);
          if (p.x > card.left + 2 && p.x < card.right - 2 && p.y > card.top + 2 && p.y < card.bottom - 2) {
            hits.push(`${id} through ${card.id}`);
            break;
          }
        }
      }
    }
    return hits;
  });
}

/** Visible relationship labels that overlap each other or a node card. */
async function labelCollisions(page: Page) {
  return page.locator(".react-flow").evaluate(canvas => {
    const visible = (el: Element) => { const s = getComputedStyle(el); const r = el.getBoundingClientRect(); return s.display !== "none" && s.visibility !== "hidden" && Number(s.opacity) > 0 && r.width > 0 && r.height > 0; };
    const labels = [...canvas.querySelectorAll(".graph-relationship-label")].filter(visible).map(el => ({ text: el.textContent?.trim() ?? "", r: el.getBoundingClientRect() }));
    // A glyph's outline and arrowheads shrink with zoom, as the label placer measures them, so below 1x its ring does too.
    const cards = [...canvas.querySelectorAll(".react-flow__node [data-graph-entity]")].flatMap(el => [...el.children].map(child => {
      const r = child.getBoundingClientRect(), width = (child as HTMLElement).offsetWidth;
      const pad = child.classList.contains("graph-entity-glyph") ? 8 * Math.min(1, width > 0 ? r.width / width : 1) : 0;
      return { text: el.getAttribute("title") ?? "", r: new DOMRect(r.left - pad, r.top - pad, r.width + pad * 2, r.height + pad * 2) };
    }));
    const overlap = (a: DOMRect, b: DOMRect) => a.left < b.right - 1 && a.right > b.left + 1 && a.top < b.bottom - 1 && a.bottom > b.top + 1;
    const out: string[] = [];
    labels.forEach((a, i) => {
      labels.slice(i + 1).forEach(b => { if (overlap(a.r, b.r)) out.push(`label "${a.text}" overlaps label "${b.text}"`); });
      cards.forEach(c => { if (overlap(a.r, c.r)) out.push(`label "${a.text}" overlaps node "${c.text}"`); });
    });
    return out;
  });
}

/** Node cards (glyph and every caption line) that overlap another card. */
async function cardOverlaps(page: Page) {
  return page.locator("[data-graph-entity]").evaluateAll(cards => {
    const boxes = cards.map(card => {
      const parts = [...card.children].filter(child => getComputedStyle(child).visibility !== "hidden" && getComputedStyle(child).display !== "none").map(child => child.getBoundingClientRect());
      return { label: card.getAttribute("title"), left: Math.min(...parts.map(r => r.left)), right: Math.max(...parts.map(r => r.right)), top: Math.min(...parts.map(r => r.top)), bottom: Math.max(...parts.map(r => r.bottom)) };
    });
    return boxes.flatMap((a, i) => boxes.slice(i + 1).filter(b => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top).map(b => `${a.label} overlaps ${b.label}`));
  });
}

/** Connections whose drawn line runs well beyond both of its ends sideways, wrapping around a column. */
async function edgesAroundColumns(page: Page) {
  return page.locator(".react-flow__edge").evaluateAll(groups => groups.flatMap(group => {
    const path = group.querySelector<SVGPathElement>(".react-flow__edge-path");
    const length = path?.getTotalLength();
    if (!path || !length) return [];
    const ends = [path.getPointAtLength(0).x, path.getPointAtLength(length).x];
    const box = path.getBBox();
    return box.x < Math.min(...ends) - 24 || box.x + box.width > Math.max(...ends) + 24 ? [group.getAttribute("data-id")] : [];
  }));
}

async function visibleLabelTexts(page: Page) {
  return page.locator(".react-flow .graph-relationship-label").evaluateAll(els => els
    .filter(el => { const s = getComputedStyle(el); return s.display !== "none" && s.visibility !== "hidden" && Number(s.opacity) > 0 && el.getBoundingClientRect().width > 0; })
    .map(el => (el.textContent ?? "").replace(/\s+/g, " ").trim()));
}

async function openAgentContext(page: Page, width: number) {
  await page.setViewportSize({ width, height: 1000 });
  await page.goto("/graph?scan=snapshot&root=agent&lens=context&capture=1");
  const drawer = page.getByTestId("graph-entity-drawer");
  // A deep-linked root opens once; closing it must keep it closed while the view changes.
  await drawer.getByRole("button", { name: "Close", exact: true }).click();
  if (width < 640) {
    const list = page.getByTestId("graph-connections-list");
    await expect(list).toBeVisible();
    await expect(list.getByRole("button")).not.toHaveCount(0);
    await page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true }).click();
  }
  const all = page.getByRole("button", { name: "All relationships", exact: true });
  if (await all.isVisible().catch(() => false)) await all.click();
  else {
    const select = page.getByLabel("Graph context", { exact: true });
    if (await select.isVisible().catch(() => false)) await select.selectOption("all");
  }
  await expect(drawer).toHaveCount(0);
  await page.locator(".react-flow__controls-fitview").click();
  await settle(page);
}

const roles = Array.from({ length: 6 }, (_, i) => node(`role-${i + 1}`, "role", `Application role ${i + 1}`));
const aws = (n: FixtureNode) => ({ ...n, dimensions: { ...n.dimensions, cloud_provider: "aws" } });
const SCENARIOS = {
  "aws account contains resources": {
    nodes: [aws(node("agent", "account", "prod-workloads")), aws(node("bucket", "data_store", "customer-pii-bucket")),
      aws(node("cluster", "cluster", "payments-eks")), aws(node("gateway", "api_gateway", "public-api-gateway"))],
    edges: [edge("agent", "bucket", "contains"), edge("agent", "cluster", "contains"), edge("agent", "gateway", "contains")],
  },
  "agent fans out to six roles": {
    nodes: [node("agent", "agent", "Developer Copilot"), ...roles],
    edges: roles.map(role => edge("agent", role.id, "can_access")),
  },
  "agents sharing an MCP server": {
    nodes: [node("role", "role", "prod-ai-admin"), node("agent", "agent", "Developer Copilot"), node("peer", "agent", "Sre Runbook Agent"),
      node("github", "server", "github-enterprise MCP"), node("filesystem", "server", "filesystem MCP")],
    edges: [edge("agent", "role", "can_access"), edge("agent", "github", "uses"), edge("agent", "filesystem", "uses"),
      edge("agent", "peer", "shares_server"), edge("peer", "filesystem", "uses")],
  },
};

for (const [name, scenario] of Object.entries(SCENARIOS)) for (const width of [1440, 390])
for (const theme of (name === "agents sharing an MCP server" && width === 390) || name === "agent fans out to six roles" ? ["dark", "light"] : ["dark"]) {
  test(`${name} reads without false routes at ${width}${theme === "light" ? " light" : ""}`, async ({ page }, info) => {
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    await fixture(page, scenario.nodes, scenario.edges);
    await openAgentContext(page, width);
    await expect.poll(() => page.locator(".react-flow__node").count()).toBeGreaterThan(1);
    expect(await edgesThroughNodes(page)).toEqual([]);
    expect(await labelCollisions(page)).toEqual([]);
    expect(await cardOverlaps(page)).toEqual([]);
    expect(await graphGrammarViolations(page)).toEqual({});
    const texts = await visibleLabelTexts(page);
    const repeats = texts.filter((text, index) => texts.indexOf(text) !== index);
    expect(repeats, `repeated labels: ${texts.join(" | ")}`).toEqual([]);
    if (name === "agent fans out to six roles") {
      const remainderLink = page.locator('.react-flow__edge[data-id^="cluster:"] .react-flow__edge-path');
      await expect(remainderLink).toHaveCount(1);
      expect(await remainderLink.evaluate(path => Number(getComputedStyle(path).opacity))).toBeGreaterThanOrEqual(0.8);
      const groupLabelSize = await page.getByTestId("cluster-pill").locator("button span").first().evaluate(label => {
        const zoom = new DOMMatrixReadOnly(getComputedStyle(document.querySelector(".react-flow__viewport")!).transform).a;
        return parseFloat(getComputedStyle(label).fontSize) * zoom;
      });
      expect(groupLabelSize, "remainder labels stay readable after Fit all").toBeGreaterThanOrEqual(11);
    }
    await page.screenshot({ path: info.outputPath(`${name.replace(/\s+/g, "-")}-${width}.png`), animations: "disabled" });
  });
}

for (const theme of ["light", "dark"] as const) test(`reference correlation reads without overlaps or false routes ${theme}`, async ({ page }, info) => {
  const proof = JSON.parse(await readFile("../examples/reference-evidence-lab/generated/correlation-proof.json", "utf8"));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  await fixture(page, proof.capture_fixture.graph.nodes, proof.capture_fixture.graph.edges, false, { stats: proof.capture_fixture.graph.stats, attack_paths: proof.capture_fixture.graph.attack_paths });
  await page.goto("/graph?scan=snapshot&layers=cloudResource,server,agent,container,package,vulnerability,tool,serviceAccount,dataStore,sourceFile");
  await expect(page.locator(".react-flow__node")).not.toHaveCount(0);
  await page.locator(".react-flow__controls-fitview").click();
  await settle(page);
  expect(await cardOverlaps(page)).toEqual([]);
  expect(await edgesThroughNodes(page)).toEqual([]);
  expect(await labelCollisions(page)).toEqual([]);
  expect(await graphGrammarViolations(page)).toEqual({});
  const recorded = page.locator('.react-flow__edge:not([data-id^="display:"])');
  await expect(recorded).toHaveCount(proof.capture_fixture.graph.edges.length);
  for (const link of proof.capture_fixture.graph.edges) {
    const drawn = page.locator(`.react-flow__edge[data-id="${link.id}"]`);
    await drawn.focus();
    await expect(drawn.locator(".react-flow__edge-path")).toHaveAttribute("marker-end", /.+/);
    await drawn.evaluate(element => (element as SVGElement).blur());
  }
  // The overview keeps all directional relationships without nine competing captions.
  expect(await visibleLabelTexts(page)).toEqual([]);
  const smallestCaption = await page.locator("[data-graph-entity] > p:first-of-type").evaluateAll(labels => {
    const viewport = document.querySelector(".react-flow__viewport")!;
    const zoom = new DOMMatrixReadOnly(getComputedStyle(viewport).transform).a;
    return Math.min(...labels.map(label => parseFloat(getComputedStyle(label).fontSize) * zoom));
  });
  expect(smallestCaption, "entity names remain readable after Fit all").toBeGreaterThanOrEqual(12);
  const clippedIds = await page.locator("[data-graph-entity] p > span[title]").evaluateAll(ids =>
    ids.filter(id => id.scrollWidth > id.clientWidth + 1).map(id => id.textContent));
  expect(clippedIds).toEqual([]);
  await page.screenshot({ path: info.outputPath(`reference-correlation-${theme}.png`), animations: "disabled" });
});

// The README context map: one agent, the MCP servers it uses, and what each server exposes.
// The capture's sample estate, in its recorded order, so a bounded query keeps the same nodes.
const AGENT_ESTATE: [string, string, string][] = [
  ["provider:aws-prod", "env:prod-ai", "hosts"], ["env:prod-ai", "cluster:eks-ai", "hosts"], ["cluster:eks-ai", "container:agent-gateway", "hosts"],
  ["container:agent-gateway", "policy:gateway-default-deny", "manages"], ["user:contractor", "sa:jit-review", "acted_as"],
  ["sa:jit-review", "role:prod-admin", "assumes"], ["role:prod-admin", "agent:developer-copilot", "can_access"],
  ["agent:developer-copilot", "server:github", "uses"], ["agent:developer-copilot", "server:filesystem", "uses"],
  ["agent:sre-runbook", "server:filesystem", "uses"], ["agent:sre-runbook", "server:slack", "uses"],
  ["agent:finance-rag", "server:snowflake", "uses"], ["agent:finance-rag", "server:slack", "uses"],
  ["agent:developer-copilot", "agent:sre-runbook", "shares_server"], ["agent:sre-runbook", "agent:finance-rag", "shares_cred"],
  ["server:github", "tool:repo-write", "provides_tool"], ["server:filesystem", "tool:exec", "provides_tool"],
  ["server:snowflake", "tool:query", "provides_tool"], ["server:slack", "tool:post", "provides_tool"],
  ["server:github", "cred:github", "exposes_cred"], ["server:snowflake", "cred:snowflake", "exposes_cred"],
  ["server:filesystem", "cred:aws", "exposes_cred"], ["server:github", "pkg:next", "depends_on"],
  ["server:filesystem", "pkg:urllib3", "depends_on"], ["server:snowflake", "pkg:protobuf", "depends_on"],
  ["server:snowflake", "pkg:langchain", "depends_on"], ["pkg:next", "cve:next", "vulnerable_to"],
  ["pkg:urllib3", "cve:urllib3", "vulnerable_to"], ["pkg:protobuf", "cve:protobuf", "vulnerable_to"],
  ["server:snowflake", "dataset:finance-docs", "accessed"], ["agent:finance-rag", "model:gpt-prod", "uses"],
  ["policy:gateway-default-deny", "tool:exec", "manages"],
];
// Inventory relationships two hops out, after one "Show more connections": both servers, github's
// tool, credential and package, filesystem's tool, and the agent sharing filesystem MCP.
const CONTEXT_MAP_IDS = ["agent:developer-copilot", "agent:sre-runbook", "cred:github", "pkg:next", "server:filesystem", "server:github",
  "tool:exec", "tool:repo-write"];
const ESTATE_TYPES: Record<string, string> = { provider: "provider", env: "environment", cluster: "cluster", container: "container", policy: "policy",
  user: "user", sa: "service_account", role: "role", agent: "agent", server: "server", tool: "tool", cred: "credential", pkg: "package",
  cve: "vulnerability", dataset: "dataset", model: "model" };

for (const theme of ["light", "dark"] as const) for (const width of [1440, 1000]) test(`an agent's context map reads as servers, tools, credentials and packages ${theme} ${width}`, async ({ page }, info) => {
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  await page.setViewportSize({ width, height: 900 });
  const ids = [...new Set(AGENT_ESTATE.flatMap(([source, target]) => [source, target]))];
  const nodes = ids.map(id => node(id, ESTATE_TYPES[id.split(":")[0]!]!, id.split(":")[1]!));
  const edges = AGENT_ESTATE.map(([source, target, relationship]) => edge(source, target, relationship));
  await fixture(page, nodes, edges);
  // The same bounded walk the API runs: requested relationship types, depth and node budget.
  await page.route("**/v1/graph/query", route => {
    const request = route.request().postDataJSON();
    const allowed = request.relationship_types?.length ? new Set(request.relationship_types) : null;
    const walk = edges.filter(item => !allowed || allowed.has(item.relationship));
    const depth = new Map<string, number>(request.roots.map((id: string) => [id, 0]));
    const queue = [...depth.keys()];
    for (let index = 0; index < queue.length; index++) {
      const id = queue[index]!;
      if (depth.get(id)! >= request.max_depth) continue;
      for (const item of walk) {
        const next = item.source === id && request.direction !== "reverse" ? item.target : item.target === id && request.direction !== "forward" ? item.source : null;
        if (next && !depth.has(next)) { depth.set(next, depth.get(id)! + 1); queue.push(next); }
      }
    }
    const kept = new Set(queue.slice(0, request.max_nodes));
    const shown = nodes.filter(item => kept.has(item.id));
    const links = walk.filter(item => kept.has(item.source) && kept.has(item.target));
    return route.fulfill({ json: { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, nodes: shown, edges: links, attack_paths: [], interaction_risks: [],
      stats: { total_nodes: shown.length, total_edges: links.length, severity_counts: {} }, roots: request.roots, direction: request.direction,
      max_depth: request.max_depth, budget: { nodes: request.max_nodes, edges: request.max_edges }, truncated: queue.length > kept.size,
      missing_roots: [], depth_by_node: Object.fromEntries([...depth].filter(([id]) => kept.has(id))), filters: {} } });
  });
  await page.goto("/graph?scan=snapshot&root=agent%3Adeveloper-copilot&lens=context&capture=1");
  await expect(page.locator('.react-flow__node[data-id="server:github"]')).toBeVisible();
  // A rooted investigation opens one hop out over every relationship; widen it with the same controls a reader uses.
  await page.getByRole("button", { name: "View & layers", exact: true }).click();
  await page.getByRole("button", { name: /^Edges/ }).click();
  await page.getByLabel("Relationship scope", { exact: true }).selectOption("inventory");
  await page.getByRole("button", { name: /^Traversal/ }).click();
  await page.getByLabel("Graph traversal depth", { exact: true }).selectOption("2");
  await page.getByRole("button", { name: "View & layers", exact: true }).click();
  await expect(page.locator('.react-flow__node[data-id="tool:repo-write"]')).toBeVisible();
  const before = await page.locator(".react-flow__node").count();
  await page.getByRole("button", { name: "Show more connections", exact: true }).click();
  await expect.poll(() => page.locator(".react-flow__node").count()).toBeGreaterThan(before);
  // The root opens its inspector; the README frame is the map alone.
  const drawer = page.getByTestId("graph-entity-drawer");
  if (await drawer.isVisible()) await drawer.getByRole("button", { name: "Close", exact: true }).click();
  await expect(drawer).toBeHidden();
  await page.locator(".react-flow__controls-fitview").click();
  await settle(page);
  const shown = await page.locator(".react-flow__node").evaluateAll(items => items.map(item => item.getAttribute("data-id")).sort());
  expect(shown).toEqual(CONTEXT_MAP_IDS);
  expect(await cardOverlaps(page)).toEqual([]);
  expect(await edgesThroughNodes(page)).toEqual([]);
  expect(await labelCollisions(page)).toEqual([]);
  expect(await edgesAroundColumns(page)).toEqual([]);
  expect(await graphGrammarViolations(page)).toEqual({});
  const smallestName = await page.locator("[data-graph-entity] > p:first-of-type").evaluateAll(labels => {
    const zoom = new DOMMatrixReadOnly(getComputedStyle(document.querySelector(".react-flow__viewport")!).transform).a;
    return Math.min(...labels.map(label => parseFloat(getComputedStyle(label).fontSize) * zoom));
  });
  expect(smallestName, "entity names stay readable at README width").toBeGreaterThanOrEqual(12);
  await page.screenshot({ path: info.outputPath(`agent-context-map-${theme}-${width}.png`), animations: "disabled" });
});

test("reset view restores the investigation defaults for the same root", async ({ page }) => {
  const scenario = SCENARIOS["agents sharing an MCP server"];
  await fixture(page, scenario.nodes, scenario.edges);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/graph?scan=snapshot&root=agent&lens=context&capture=1&context_view=identity");
  await page.getByTestId("graph-entity-drawer").getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Reset view", exact: true }).click();
  await expect(page).toHaveURL(/context_view=all/);
  await expect(page).toHaveURL(/root=agent/);
  await expect(page.getByRole("button", { name: "All relationships", exact: true })).toHaveAttribute("aria-pressed", "true");
});

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) test(`shared account preserves shared-server evidence ${theme} ${width}`, async ({ page }) => {
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    const nodes = [node("agent", "agent", "Root Agent"), node("peer", "agent", "Peer Agent"), node("account", "account", "Common Account")];
    await fixture(page, nodes, [edge("account", "agent", "contains"), edge("account", "peer", "contains"), edge("agent", "peer", "shares_server")]);
    await openAgentContext(page, width);
    await expect(page.locator(".react-flow__node")).toHaveCount(3);
    await expect(page.locator('.react-flow__edge[data-id="agent:shares_server:peer"]')).toHaveCount(1);
  });

  test(`same-root reload preserves the selected drawer entity and action ${theme}`, async ({ page }) => {
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await fixture(page, [node("agent", "agent", "Root Agent"), node("role", "role", "Selected Role")], [edge("agent", "role", "can_access")], true);
    await page.goto("/graph?scan=snapshot&root=agent&lens=context&capture=1");
    const drawer = page.getByTestId("graph-entity-drawer");
    await drawer.getByRole("button", { name: "Close", exact: true }).click();
    await page.locator('.react-flow__node[data-id="role"]').click();
    await expect(drawer.getByRole("heading", { name: "Selected Role", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Show more connections", exact: true }).click();
    await expect(page.getByRole("button", { name: "Show more connections", exact: true })).toBeVisible();
    await expect(drawer.getByRole("heading", { name: "Selected Role", exact: true })).toBeVisible();
    const request = page.waitForRequest(r => new URL(r.url()).pathname === "/v1/graph/query");
    await drawer.getByRole("button", { name: "Expand", exact: true }).click();
    expect((await request).postDataJSON()).toMatchObject({ roots: ["role"] });
  });
}

test("a correlation opens on a readable neighbourhood, never a lone card", async ({ page }, info) => {
  const proof = JSON.parse(await readFile("../examples/reference-evidence-lab/generated/correlation-proof.json", "utf8"));
  await page.setViewportSize({ width: 1440, height: 900 });
  await fixture(page, proof.capture_fixture.graph.nodes, proof.capture_fixture.graph.edges, false, { stats: proof.capture_fixture.graph.stats, attack_paths: proof.capture_fixture.graph.attack_paths });
  await page.goto("/graph?capture=1&scan=snapshot&layers=cloudResource,server,agent,container,package,vulnerability,tool,serviceAccount,dataStore,sourceFile");
  await expect(page.locator(".react-flow__node")).not.toHaveCount(0);
  await settle(page);
  // No Fit all click: the first frame itself must show whole, readable cards in context.
  const frame = await page.locator(".react-flow").evaluate(canvas => {
    const b = canvas.getBoundingClientRect();
    const zoom = new DOMMatrixReadOnly(getComputedStyle(canvas.querySelector(".react-flow__viewport")!).transform).a;
    const cards = [...canvas.querySelectorAll<HTMLElement>("[data-graph-entity]")];
    const whole = cards.filter(e => { const r = e.getBoundingClientRect(); return r.left >= b.left && r.right <= b.right && r.top >= b.top && r.bottom <= b.bottom; });
    const label = Math.min(...whole.map(card => parseFloat(getComputedStyle(card.querySelector("p")!).fontSize) * zoom));
    return { whole: whole.length, label };
  });
  expect(frame.whole).toBeGreaterThanOrEqual(3);
  expect(frame.label).toBeGreaterThanOrEqual(12);
  await page.screenshot({ path: info.outputPath("correlation-first-frame.png"), animations: "disabled" });
});

for (const theme of ["light", "dark"] as const) test(`provider marks read as part of the node ${theme}`, async ({ page }, info) => {
  const inherited = { cloud_provider_basis: "inherited:hosts", cloud_provider_source: { node_id: "cluster", label: "payments-eks", entity_type: "cluster" } };
  const worker = { ...node("worker", "container", "ledger-worker"), attributes: inherited, dimensions: { environment: "staging", cloud_provider: "aws" } };
  const nodes = [aws(node("agent", "account", "prod-workloads")), aws(node("cluster", "cluster", "payments-eks")), worker,
    aws(node("bucket", "data_store", "customer-pii-bucket")),
    { ...node("warehouse", "cloud_resource", "analytics-wh"), attributes: { resource_type: "warehouse" }, dimensions: { environment: "prod", cloud_provider: "snowflake" } }];
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  await fixture(page, nodes, [edge("agent", "cluster", "contains"), edge("cluster", "worker", "hosts"), edge("agent", "bucket", "contains"),
    edge("worker", "warehouse", "can_access")]);
  await openAgentContext(page, 1440);
  await expect(page.locator(".react-flow [data-finding-signal]")).toHaveCount(0);
  const marks = page.locator(".react-flow [data-graph-source-badge]");
  // One mark per scope: the AWS account root and the cross-vendor Snowflake hop; children that match their scope stay unmarked.
  await expect(marks).toHaveCount(2);
  const measured = await marks.evaluateAll(all => {
    const luminance = (color: string) => {
      const [r, g, b] = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(v => v / 255).map(v => v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
      return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
    };
    const canvas = getComputedStyle(document.querySelector(".react-flow")!).backgroundColor;
    return all.map(mark => {
      const style = getComputedStyle(mark);
      const [hi, lo] = [luminance(style.outlineColor), luminance(canvas)].sort((a, b) => b - a);
      const badgeRect = mark.getBoundingClientRect();
      const caption = mark.closest("[data-graph-entity]")?.querySelector(":scope > p");
      const captionRects = [...(caption?.querySelectorAll("span") ?? [])].map(span => span.getBoundingClientRect());
      const overlapsCaption = captionRects.some(rect => badgeRect.left < rect.right && badgeRect.right > rect.left && badgeRect.top < rect.bottom && badgeRect.bottom > rect.top);
      return { overlapsCaption, basis: mark.getAttribute("data-provider-basis"), title: mark.getAttribute("title"), outline: style.outlineStyle,
        background: style.backgroundColor, filter: getComputedStyle(mark.querySelector("img")!).filter,
        glyph: mark.querySelector("img")!.getBoundingClientRect().width, contrast: (hi! + 0.05) / (lo! + 0.05) };
    });
  });
  for (const mark of measured) {
    expect(mark.glyph, "vendor logo remains legible on the fitted canvas").toBeGreaterThanOrEqual(24);
    expect(mark.background).toBe("rgb(255, 255, 255)");
    expect(mark.filter).toBe("none");
    expect(mark.overlapsCaption).toBe(false);
    expect(mark.contrast, "mark outline contrast against the canvas").toBeGreaterThanOrEqual(3);
  }
  expect(measured.map(mark => mark.title).sort()).toEqual(["Source: AWS", "Source: Snowflake"]);
  await expect(page.locator('[data-id="worker"] [data-graph-source-badge]')).toHaveCount(0);
  await expect(page.locator('.react-flow [data-node-badge="provider"]')).toHaveCount(0);
  // The canvas keeps one type line; the environment stays in the drawer, not as a chip.
  await expect(page.locator('[data-id="worker"] [data-entity-role]')).toBeVisible();
  await expect(page.locator('[data-id="worker"] [data-node-badge]')).toHaveCount(0);
  // Names wrap only between segments, without a lone short tail.
  const lines = await page.locator('[data-id="bucket"] [data-graph-entity] > p').first().evaluate(label => {
    const rows = new Map<number, string>();
    for (const span of label.querySelectorAll(":scope > span")) {
      if (span.getClientRects().length !== 1) return ["split inside a segment"];
      const top = Math.round(span.getBoundingClientRect().top);
      rows.set(top, (rows.get(top) ?? "") + span.textContent);
    }
    return [...rows.values()];
  });
  expect(lines.join("")).toBe("customer-pii-bucket");
  if (lines.length > 1) expect(Math.min(...lines.map(l => l.length)) / Math.max(...lines.map(l => l.length))).toBeGreaterThanOrEqual(0.6);
  await page.screenshot({ path: info.outputPath(`provider-marks-${theme}.png`), animations: "disabled" });
});


async function readableCloudFrame(page: Page) {
  const measured = await page.locator(".react-flow").evaluate(canvas => {
    const zoom = new DOMMatrixReadOnly(getComputedStyle(canvas.querySelector(".react-flow__viewport")!).transform).a;
    const names = [...canvas.querySelectorAll("[data-semantic-name]")];
    const boxes = [...canvas.querySelectorAll("[data-graph-entity]")].map(node => node.getBoundingClientRect());
    return {
      smallestName: Math.min(...names.map(node => parseFloat(getComputedStyle(node).fontSize) * zoom)),
      widthShare: (Math.max(...boxes.map(box => box.right)) - Math.min(...boxes.map(box => box.left))) / canvas.clientWidth,
    };
  });
  expect(measured.smallestName).toBeGreaterThanOrEqual(13.9);
  expect(measured.widthShare).toBeGreaterThanOrEqual(0.75);
}

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`cloud roles and finding ownership stay readable ${theme} ${width}`, async ({ page }, info) => {
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    await page.setViewportSize({ width, height: 900 });
    // The same owning fixture used by the product screenshot pipeline.
    const { buildScopeShowcase } = await import("../scripts/product-proof-scope-showcase.mjs");
    const catalog = JSON.parse(await readFile("fixtures/gallery-advisories.json", "utf8"));
    const showcase = buildScopeShowcase("cloud", {
      base: { scan_id: "snapshot" },
      node: (id: string, type: string, label: string, severity: string, risk_score: number, attributes: Record<string, unknown>) => ({ ...node(id, type, label), severity, risk_score, attributes }),
      edge: (source: string, target: string, relationship: string, weight: number, evidence: Record<string, unknown>) => ({ ...edge(source, target, relationship), weight, evidence: { tier: "modeled_infrastructure", source: "gallery-fixture", ...evidence } }),
      advisory: (id: string) => catalog.advisories.find((item: { canonical_id: string }) => item.canonical_id === id) ?? catalog.advisories.find((item: { id: string }) => item.id === id),
      referenceCve: { label: "unused", attributes: {} },
    });
    const entries: FixtureNode[] = showcase.nodes, links: FixtureEdge[] = showcase.edges;
    await fixture(page, entries, links, false, { stats: showcase.stats, attack_paths: showcase.attack_paths });
    await routeNodeAggregates(page, ownedFindingAggregates(entries, links));
    await page.goto("/graph?scan=snapshot&rollup=0&capture=1&layers=account,cluster,apiGateway,container,role,dataStore,vulnerability,misconfiguration");
    if (width < 640) await page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true }).click();
    await page.getByRole("button", { name: "Show supporting context (4)", exact: true }).click();
    // The selected path's terminal CVE stays on the spine; the other three findings group under their owners.
    // The supporting account remains a node connected by its recorded containment.
    await expect.poll(async () => await page.locator('.react-flow__node:not([data-id^="display:"])').count() + await page.locator("[data-boundary-frame]").count()).toBe(8);
    await expect(page.locator('[data-graph-entity="finding-group"]')).toHaveCount(0);
    // Supporting containment links remain visible with the account node.
    if (width >= 640) await expect(page.getByLabel("Visible relationship evidence")).toContainText("Modeled 8");
    await settle(page);
    expect(await graphGrammarViolations(page)).toEqual({});
    if (width >= 640) await readableCloudFrame(page);
    else {
      const order = await page.locator('.react-flow__node').evaluateAll(nodes => [...nodes]
        .sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top).slice(0, 4).map(node => node.getAttribute("data-id")));
      expect(order.slice(1)).toEqual(["gateway:public", "container:checkout", "cve:next"]);
      const firstTop = await page.locator('.react-flow').evaluate(canvas => {
        const first = [...canvas.querySelectorAll("[data-graph-entity]")]
          .map(node => node.getBoundingClientRect().top).sort((a, b) => a - b)[0];
        if (first === undefined) throw new Error("The reading path has no visible nodes");
        return first - canvas.getBoundingClientRect().top;
      });
      expect(firstTop, "the reading path starts below the controls, without a blank screen").toBeGreaterThanOrEqual(48);
      expect(firstTop).toBeLessThanOrEqual(96);
      await expect(page.locator('[data-id="gateway:public"] [data-entity-role]')).toHaveText("Amazon API Gateway");
    }
    await page.screenshot({ path: info.outputPath(`cloud-branches-${theme}-${width}.png`), animations: "disabled" });
    if (width >= 640) {
      const count = page.getByRole("button", { name: "Expand 1 finding for checkout-runtime-role", exact: true });
      await count.hover();
      await expect(page.getByRole("tooltip")).toContainText("highest severity: high");
      expect(await page.getByRole("tooltip").evaluate(tip => {
        const a = tip.getBoundingClientRect();
        return [...document.querySelectorAll("[data-graph-entity] > p, [data-entity-role], .graph-entity-glyph")].filter(el => {
          const b = el.getBoundingClientRect();
          return a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
        }).map(el => el.textContent);
      })).toEqual([]);
      await page.screenshot({ path: info.outputPath(`cloud-finding-tooltip-${theme}.png`), animations: "disabled" });
      await count.click();
      await expect(page.locator('[data-id="finding:wildcard"]')).toHaveCount(1);
      await expect(page.locator('[data-id="role:checkout"] [data-finding-disclosure]')).toHaveCount(0);
      await page.getByRole("button", { name: "Expand findings (2 grouped)", exact: true }).click();
      await page.getByRole("button", { name: "Collapse findings", exact: true }).click();
      await page.getByRole("heading", { name: "Investigation", exact: true }).click();
    }
    await page.getByRole("button", { name: "Expand findings (3 grouped)", exact: true }).click();
    // Every recorded node is drawn, the account as the boundary on desktop; the internet anchor is display context beside them.
    await expect.poll(async () => await page.locator('.react-flow__node:not([data-id^="display:"])').count() + await page.locator("[data-boundary-frame]").count()).toBe(entries.length);
    if (width < 640) {
      await settle(page);
      const zoom = await page.locator(".react-flow__viewport").evaluate(el => new DOMMatrixReadOnly(getComputedStyle(el).transform).a);
      expect(zoom).toBeGreaterThanOrEqual(0.8);
      await expect(page.getByRole("group", { name: "Navigate loaded graph nodes" })).toBeVisible();
      await page.getByRole("button", { name: "Next graph node", exact: true }).click();
      await settle(page);
      await page.screenshot({ path: info.outputPath(`cloud-roles-initial-${theme}-${width}.png`), animations: "disabled" });
    }
    await page.locator(".react-flow__controls-fitview").click();
    await settle(page);
    for (const caption of ["AWS IAM role", "Amazon EKS", "Amazon S3 bucket"]) {
      await expect(page.getByText(caption, { exact: true })).toBeVisible();
    }
    await expect(page.locator("[data-graph-category]")).toHaveCount(0);
    // Counts for children already visible are tooltip details, never extra pills.
    await expect(page.locator("[data-asset-connections]")).toHaveCount(0);
    expect(await cardOverlaps(page)).toEqual([]);
    expect(await edgesThroughNodes(page)).toEqual([]);
    expect(await labelCollisions(page)).toEqual([]);
    // A containing account sits before what it contains, so no link loops around a column.
    expect(await edgesAroundColumns(page)).toEqual([]);
    expect(await graphGrammarViolations(page)).toEqual({});
    // The provider plate must clear the name even at the expanded graph's fit zoom.
    expect(await page.locator("[data-graph-source-badge]").evaluateAll(badges => badges.flatMap(badge => {
      const a = badge.getBoundingClientRect();
      const name = badge.closest("[data-graph-entity]")?.querySelector(":scope > p");
      return [...(name?.querySelectorAll("span") ?? [])].filter(span => {
        const b = span.getBoundingClientRect();
        return a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
      }).map(span => span.textContent);
    }))).toEqual([]);
    // Overview connectors stay quiet; every recorded direction remains available
    // to keyboard users, including links whose direction opposes reading order.
    for (const link of links) {
      const drawn = page.locator(`.react-flow__edge[data-id="${link.id}"]`);
      if (!await drawn.count()) continue; // Account containment is represented by its scope caption.
      await drawn.focus();
      await expect(drawn.locator(".react-flow__edge-path")).toHaveAttribute("marker-end", /.+/);
      await drawn.evaluate(element => (element as SVGElement).blur());
    }
    const labels = await visibleLabelTexts(page);
    if (width >= 640) {
      expect(labels).toEqual([]); // Captions appear on focus; the overview stays quiet.
      const access = page.getByRole("group", { name: /Has Permission.*relationship from checkout-runtime-role to customer-pii-bucket/ });
      await access.focus();
      await expect(page.locator(".graph-relationship-label").filter({ hasText: /Permission/i })).toBeVisible();
      await page.screenshot({ path: info.outputPath(`cloud-relationship-focus-${theme}.png`), animations: "disabled" });
      await page.getByRole("heading", { name: "Investigation", exact: true }).click();
    } else {
      // Explicit Fit all provides an overview; the initial mobile camera above stays readable.
      await expect(page.getByRole("group", { name: /Has Permission.*relationship from checkout-runtime-role to customer-pii-bucket/ })).toHaveCount(1);
    }
    await page.screenshot({ path: info.outputPath(`cloud-roles-${theme}-${width}.png`), animations: "disabled" });
    if (width >= 640) {
      const clipped = await page.locator(".react-flow").evaluate(canvas => {
        const b = canvas.getBoundingClientRect();
        return [...canvas.querySelectorAll("[data-graph-entity]")].filter(el => {
          const r = el.getBoundingClientRect();
          return r.left < b.left || r.right > b.right || r.top < b.top || r.bottom > b.bottom;
        }).map(el => el.textContent);
      });
      expect(clipped).toEqual([]);
      await readableCloudFrame(page);
      await page.locator('[data-id="finding:waf"] [data-graph-entity]').click();
      await expect(page.getByTestId("graph-entity-drawer")).toContainText("Public API stage has no WAF association");
      await page.screenshot({ path: info.outputPath(`cloud-finding-inspector-${theme}.png`), animations: "disabled" });
      await page.getByRole("button", { name: "Collapse findings", exact: true }).click();
      // The supporting account remains a node connected by its recorded containment.
    await expect.poll(async () => await page.locator('.react-flow__node:not([data-id^="display:"])').count() + await page.locator("[data-boundary-frame]").count()).toBe(8);
      await expect(page.locator('[data-graph-entity="finding-group"]')).toHaveCount(0);
      await expect(page.getByTestId("graph-entity-drawer")).toHaveCount(0);
    }
  });
}

for (const theme of ["light", "dark"] as const) test(`independent environment chains keep credential links clear ${theme}`, async ({ page }, info) => {
  await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
  await page.setViewportSize({ width: 1440, height: 900 });
  const { buildScopeShowcase } = await import("../scripts/product-proof-scope-showcase.mjs");
  const catalog = JSON.parse(await readFile("fixtures/gallery-advisories.json", "utf8"));
  const showcase = buildScopeShowcase("environment", {
    base: { scan_id: "snapshot" },
    node: (id: string, type: string, label: string, severity: string, risk_score: number, attributes: Record<string, unknown>) => ({ ...node(id, type, label), severity, risk_score, attributes }),
    edge: (source: string, target: string, relationship: string, weight: number, evidence: Record<string, unknown>) => ({ ...edge(source, target, relationship), weight, evidence }),
    advisory: (id: string) => catalog.advisories.find((item: { canonical_id: string }) => item.canonical_id === id) ?? catalog.advisories.find((item: { id: string }) => item.id === id),
    referenceCve: { label: "CVE-2023-4863", severity: "high", risk_score: 8.8, attributes: { canonical_id: "CVE-2023-4863", is_kev: true } },
  });
  await fixture(page, showcase.nodes, showcase.edges, false, { stats: showcase.stats, attack_paths: showcase.attack_paths });
  await routeNodeAggregates(page, ownedFindingAggregates(showcase.nodes, showcase.edges));
  await page.goto("/graph?scan=snapshot&rollup=0&capture=1&layers=environment,agent,server,container,package,vulnerability,credential,dataStore");
  await expect(page.locator('[data-id="cred:tickets"]')).toHaveCount(1);
  await settle(page);
  expect(await cardOverlaps(page)).toEqual([]);
  expect(await edgesThroughNodes(page)).toEqual([]);
  expect(await graphGrammarViolations(page)).toEqual({});
  await page.screenshot({ path: info.outputPath(`environment-chains-${theme}.png`), animations: "disabled" });
  await page.getByRole("button", { name: "Expand findings (1 grouped)", exact: true }).click();
  await settle(page);
  expect(await cardOverlaps(page)).toEqual([]);
  expect(await edgesThroughNodes(page)).toEqual([]);
  expect(await graphGrammarViolations(page)).toEqual({});
  await page.screenshot({ path: info.outputPath(`environment-expanded-${theme}.png`), animations: "disabled" });
});

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`exposure story hierarchy opens legibly ${theme} ${width}`, async ({ page }, info) => {
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    await page.setViewportSize({ width, height: 900 });
    // The same owning fixture used by the product screenshot pipeline.
    const { buildScopeShowcase } = await import("../scripts/product-proof-scope-showcase.mjs");
    const catalog = JSON.parse(await readFile("fixtures/gallery-advisories.json", "utf8"));
    const showcase = buildScopeShowcase("cloud", {
      base: { scan_id: "snapshot" },
      node: (id: string, type: string, label: string, severity: string, risk_score: number, attributes: Record<string, unknown>) => ({ ...node(id, type, label), severity, risk_score, attributes }),
      edge: (source: string, target: string, relationship: string, weight: number, evidence: Record<string, unknown>) => ({ ...edge(source, target, relationship), weight, evidence: { tier: "modeled_infrastructure", source: "gallery-fixture", ...evidence } }),
      advisory: (id: string) => catalog.advisories.find((item: { canonical_id: string }) => item.canonical_id === id) ?? catalog.advisories.find((item: { id: string }) => item.id === id),
      referenceCve: { label: "unused", attributes: {} },
    });
    const entries: FixtureNode[] = showcase.nodes, links: FixtureEdge[] = showcase.edges;
    await fixture(page, entries, links, false, { stats: showcase.stats, attack_paths: showcase.attack_paths });
    await routeNodeAggregates(page, ownedFindingAggregates(entries, links));
    await page.goto("/graph?scan=snapshot&rollup=0&capture=1&layers=account,cluster,apiGateway,container,role,dataStore,vulnerability,misconfiguration");
    if (width < 640) await page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true }).click();

    await expect(page.getByRole("button", { name: "Show supporting context (4)", exact: true })).toBeVisible();
    await expect(page.locator('[data-boundary-frame]')).toHaveCount(0);
    await expect(page.locator('[data-id="cluster:payments"]')).toHaveCount(0);
    // An opaque foreground circle previously hid every continent.
    await expect(page.locator('[data-internet-globe] > circle:last-child')).toHaveAttribute("fill", "none");
    expect(await page.locator('[data-internet-globe] path').count()).toBeGreaterThan(2);
    await settle(page);
    expect(await cardOverlaps(page)).toEqual([]);
    expect(await edgesThroughNodes(page)).toEqual([]);
    if (width >= 640) {
      const reading = await page.locator(".react-flow").evaluate(canvas => {
        const zoom = new DOMMatrixReadOnly(getComputedStyle(canvas.querySelector(".react-flow__viewport")!).transform).a;
        const names = [...canvas.querySelectorAll("[data-semantic-name]")];
        return Math.min(...names.map(n => parseFloat(getComputedStyle(n).fontSize) * zoom));
      });
      expect(reading).toBeGreaterThanOrEqual(15.9);
    }
    if (width >= 640) {
      const straight = await page.locator('.react-flow__edge[data-id="display:internet:gateway:public"] .react-flow__edge-path').evaluate(path => {
        const line = path as SVGPathElement;
        const ys = [0, 0.25, 0.5, 0.75, 1].map(t => line.getPointAtLength(line.getTotalLength() * t).y);
        return Math.max(...ys) - Math.min(...ys);
      });
      expect(straight, "same-row Internet entry stays straight").toBeLessThan(1);
    }
    await page.screenshot({ path: info.outputPath(`story-first-${theme}-${width}.png`), animations: "disabled" });
    await page.getByRole("button", { name: "Show supporting context (4)", exact: true }).click();
    await settle(page);
    await expect(page.locator('[data-boundary-frame]')).toHaveCount(0);
    await expect(page.getByText("prod-workloads", { exact: true })).toBeVisible();
    await expect(page.locator('.react-flow__edge[data-id*="contains"]')).not.toHaveCount(0);
    if (width >= 640) {
      const spread = await page.locator('.react-flow__edge[data-id="display:internet:gateway:public"] .react-flow__edge-path').evaluate(path => {
        const line = path as SVGPathElement;
        const ys = [0, 0.25, 0.5, 0.75, 1].map(t => line.getPointAtLength(line.getTotalLength() * t).y);
        return Math.max(...ys) - Math.min(...ys);
      });
      expect(spread, "account context must not bend the level exposure entry").toBeLessThan(1);
    }
    expect(await cardOverlaps(page)).toEqual([]);
    expect(await edgesThroughNodes(page)).toEqual([]);
    await page.screenshot({ path: info.outputPath(`story-context-${theme}-${width}.png`), animations: "disabled" });
  });
}
