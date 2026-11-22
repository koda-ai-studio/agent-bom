import { readFile } from "node:fs/promises";
import { test, expect, type Page } from "@playwright/test";
import { routeNodeAggregates, withSemanticLayer } from "./helpers/graph-rollup-mocks";
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


test("zz probe marks", async ({ page }) => {
  const nodes = [aws(node("agent", "account", "prod-workloads")), aws(node("cluster", "cluster", "payments-eks")), aws(node("bucket", "data_store", "customer-pii-bucket"))];
  await fixture(page, nodes, [edge("agent", "cluster", "contains"), edge("agent", "bucket", "contains")]);
  await openAgentContext(page, 1440);
  console.log(JSON.stringify(await page.locator(".react-flow [data-graph-source-badge]").evaluateAll(all => all.map(m => ({
    mark: m.getBoundingClientRect().width, cls: m.className, img: m.querySelector("img")!.getBoundingClientRect().width, imgcls: m.querySelector("img")!.className,
    glyph: m.closest(".graph-entity-glyph")!.getBoundingClientRect().width })))));
});
