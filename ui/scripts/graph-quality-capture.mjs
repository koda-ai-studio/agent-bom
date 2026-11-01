/** Rendered graph regression evidence. Output is private unless explicitly published. */
import fs from "node:fs/promises";
import path from "node:path";
import { expect } from "@playwright/test";
import { auditRenderedGraph } from "./graph-visual-audit.mjs";

export async function runGraphQualityCapture({ newCapturePage, buildScopeShowcase, graph, baseUrl, output, fitReactFlow }) {
  await fs.mkdir(output, { recursive: true });
  const subset = (ids) => {
    const nodes = structuredClone(graph.nodes.filter(node => ids.includes(node.id)));
    const edges = structuredClone(graph.edges.filter(edge => ids.includes(edge.source) && ids.includes(edge.target)));
    return { ...graph, nodes, edges, attack_paths: [], stats: { ...graph.stats, total_nodes: nodes.length, total_edges: edges.length, attack_path_count: 0 }, pagination: { total: nodes.length, offset: 0, limit: nodes.length, has_more: false } };
  };
  const identity = subset(["user:contractor", "sa:jit-review", "role:prod-admin", "agent:developer-copilot", "server:github"]);
  identity.nodes.find(n => n.id === "role:prod-admin").attributes.provider = "aws";
  identity.nodes.find(n => n.id === "user:contractor").attributes.provider = "okta";
  identity.edges[0].evidence = {};
  identity.edges[1].evidence = { tier: "static_scan", source: "synthetic-identity-config" };
  const dependency = buildScopeShowcase("repository");
  const keep = new Set(["repo:payments", "dir:src", "source:server", "pkg:next", "cve:next"]);
  dependency.nodes = dependency.nodes.filter(n => keep.has(n.id));
  dependency.edges = dependency.edges.filter(e => keep.has(e.source) && keep.has(e.target));
  dependency.attack_paths = [];
  dependency.stats = { ...dependency.stats, total_nodes: dependency.nodes.length, total_edges: dependency.edges.length, attack_path_count: 0 };
  dependency.pagination = { total: dependency.nodes.length, offset: 0, limit: dependency.nodes.length, has_more: false };
  const crossVendor = subset(["agent:finance-rag", "server:snowflake", "tool:query", "cred:snowflake", "dataset:finance-docs", "model:gpt-prod"]);
  crossVendor.nodes.find(n => n.id === "agent:finance-rag").attributes.agent_type = "codex-cli";
  crossVendor.nodes.find(n => n.id === "server:snowflake").attributes.provider = "snowflake";
  crossVendor.edges.forEach((edge, i) => { edge.evidence = i === 0 ? { tier: "runtime_observed", source: "synthetic-runtime-fixture" } : i === 1 ? {} : { tier: "static_scan", source: "synthetic-config-fixture" }; });
  const cases = [["repository", buildScopeShowcase("repository")], ["cloud", buildScopeShowcase("cloud")], ["identity", identity], ["dependency", dependency], ["ai-mcp", buildScopeShowcase("environment")], ["cross-vendor", crossVendor]];
  const cyclic = structuredClone(dependency);
  const prototype = cyclic.nodes.find(n => n.id === "pkg:next");
  for (const id of ["pkg:shared", "pkg:helper"]) cyclic.nodes.push({ ...structuredClone(prototype), id, label: `${id.slice(4)}-library@1.0.0`, severity: "none", risk_score: 0, attributes: { simulated: true, version: "1.0.0", ecosystem: "npm" } });
  for (const [source, target] of [["source:server", "pkg:shared"], ["pkg:next", "pkg:shared"], ["pkg:shared", "pkg:helper"], ["pkg:helper", "pkg:shared"]]) cyclic.edges.push({ ...structuredClone(cyclic.edges[0]), id: `${source}->${target}:depends_on`, source, target, relationship: "depends_on" });
  const grouped = structuredClone(dependency);
  grouped.nodes = [grouped.nodes[0], ...Array.from({ length: 90 }, (_, i) => ({ ...structuredClone(prototype), id: `pkg:fixture-${i}`, label: `workspace-component-${i}@1.0.0`, severity: "none", risk_score: 0, attributes: { simulated: true, version: "1.0.0", ecosystem: "npm" } }))];
  grouped.edges = grouped.nodes.slice(1).map(n => ({ ...structuredClone(grouped.edges[0]), id: `bundle-${n.id}`, source: grouped.nodes[0].id, target: n.id, relationship: "contains" }));
  cases.push(["shared-cycle", cyclic], ["grouped", grouped]);
  // Recompute synthetic subset statistics; no path analysis is claimed for subsets.
  for (const [, fixture] of cases) {
    const counts = key => fixture.nodes.reduce((acc, n) => ({ ...acc, [n[key]]: (acc[n[key]] ?? 0) + 1 }), {});
    const severities = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const n of fixture.nodes) if (["vulnerability", "misconfiguration"].includes(n.entity_type) && n.severity in severities) severities[n.severity]++;
    fixture.pagination = { total: fixture.nodes.length, offset: 0, limit: fixture.nodes.length, has_more: false };
    fixture.stats = { ...fixture.stats, total_nodes: fixture.nodes.length, total_edges: fixture.edges.length, node_types: counts("entity_type"), severity_counts: severities,
      relationship_types: fixture.edges.reduce((acc, e) => ({ ...acc, [e.relationship]: (acc[e.relationship] ?? 0) + 1 }), {}),
      analysis_status: fixture.attack_paths.length ? fixture.stats.analysis_status : {} };
  }
  const results = [];
  for (const [name, fixture] of cases) for (const theme of ["dark", "light"]) for (const viewport of [{ width: 1440, height: 900 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
    const key = `${name}-${theme}-${viewport.width}`;
    const started = performance.now();
    const page = await newCapturePage(theme, viewport, fixture);
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    try {
      await page.goto(`${baseUrl}/graph?lens=estate&rollup=0&scan=${graph.scan_id}&capture=1`);
      await page.getByRole("heading", { name: "Investigation", exact: true }).waitFor();
      if (viewport.width < 640) {
        await expect(page.getByTestId("graph-path-list")).toBeVisible();
        await page.screenshot({ path: path.join(output, `${key}-paths.png`) });
        await page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true }).click();
      }
      await expect(page.locator(".react-flow__node").first()).toBeVisible();
      if (viewport.width >= 640) await fitReactFlow(page);
      await page.evaluate(() => window.scrollTo(0, 0));
      await expect(page.getByLabel("Visible relationship evidence")).toBeVisible();
      // Camera animation and readable glyph resizing have separate layout turns.
      await expect.poll(async () => (await page.evaluate(auditRenderedGraph, { edges: fixture.edges })).misalignedHandles,
        { timeout: 5_000, message: "Rendered relationship endpoints settle on the entity glyphs" }).toEqual([]);
      const audit = await page.evaluate(auditRenderedGraph, { edges: fixture.edges });
      await fs.writeFile(path.join(output, `${key}-geometry.json`), JSON.stringify(await page.locator(".react-flow__edge").evaluateAll(edges => edges.map(e => ({ id: e.dataset.id, path: e.querySelector(".react-flow__edge-path")?.outerHTML, markers: [...document.querySelectorAll("marker")].map(m => m.outerHTML) }))), null, 2));
      const geometry = await page.locator(".react-flow__node").evaluateAll(nodes => {
        const rects = nodes.map(n => ({ id: n.dataset.id, r: n.getBoundingClientRect() }));
        const overlaps = rects.flatMap((a, i) => rects.slice(i + 1).filter(b => a.r.left < b.r.right && a.r.right > b.r.left && a.r.top < b.r.bottom && a.r.bottom > b.r.top).map(b => [a.id, b.id]));
        const canvas = document.querySelector(".react-flow").getBoundingClientRect();
        const clipped = window.innerWidth >= 640 ? rects.filter(({ r }) => r.left < canvas.left - 2 || r.right > canvas.right + 2 || r.top < canvas.top - 2 || r.bottom > canvas.bottom + 2).map(({ id }) => id) : [];
        return { overlaps, clipped, horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth };
      });
      await page.screenshot({ path: path.join(output, `${key}.png`) });
      if (geometry.overlaps.length || geometry.clipped.length || geometry.horizontalOverflow || audit.misalignedHandles.length || audit.logos.some(logo => !logo.loaded || logo.overlapsGlyph) || errors.length) throw new Error(JSON.stringify({ geometry, audit, errors }));
      const finding = fixture.nodes.find(n => n.entity_type === "misconfiguration") ?? fixture.nodes.find(n => n.entity_type === "vulnerability");
      if (finding) {
        const target = page.locator(`.react-flow__node[data-id="${finding.id}"]`);
        if (await target.count()) {
          await target.focus();
          await page.keyboard.press("Enter");
          await expect(page.getByLabel("Finding investigation")).toBeVisible();
          await page.waitForTimeout(400);
          await page.screenshot({ path: path.join(output, `${key}-finding.png`) });
          await page.getByRole("tab", { name: "Relationships", exact: true }).click();
          await expect(page.getByText(/recorded relationship.*all pages loaded/)).toBeVisible();
          const related = fixture.edges.find(e => e.source === finding.id || e.target === finding.id);
          if (related) {
            const neighbor = fixture.nodes.find(n => n.id === (related.source === finding.id ? related.target : related.source));
            await expect(page.getByRole("button", { name: neighbor.label, exact: true })).toBeVisible();
          }
          await page.getByText("Export investigation", { exact: true }).click();
          const downloaded = page.waitForEvent("download");
          await page.getByRole("button", { name: "Download investigation JSON", exact: true }).click();
          await (await downloaded).saveAs(path.join(output, `${key}-investigation.json`));
          await page.screenshot({ path: path.join(output, `${key}-relationships.png`) });
          await page.getByRole("button", { name: "Close", exact: true }).click();
        }
      }
      if (name === "grouped") {
        const expand = page.getByRole("button", { name: /^Expand 90/ });
        await expect(expand).toBeVisible();
        await expand.click();
        await expect(page.getByText("Graph · 91 nodes · 90 relationships", { exact: true })).toBeVisible();
        // React Flow virtualizes offscreen children after expansion.
        await expect(expand).toHaveCount(0);
        await page.waitForTimeout(400);
        await expect(page.locator(".react-flow__node").first()).toBeVisible();
        await page.screenshot({ path: path.join(output, `${key}-expanded.png`) });
      } else {
        const edge = fixture.edges[0];
        if (edge) {
          const arrow = page.locator(`.react-flow__edge[data-id="${edge.id}"]`);
          await arrow.focus();
          if (edge.direction !== "undirected") await expect(arrow.locator(".react-flow__edge-path")).toHaveAttribute("marker-end", /url/);
          await page.keyboard.press("Enter");
          await expect(page.getByLabel("Relationship details", { exact: true })).toBeVisible();
          await expect(page.getByLabel("Relationship summary")).toBeVisible();
          await page.screenshot({ path: path.join(output, `${key}-edge.png`) });
        }
      }
      results.push({ key, elapsedMs: Math.round(performance.now() - started), audit, geometry, errors, evidence: await page.getByLabel("Visible relationship evidence").textContent() });
      console.log(`Graph quality capture ${key}: ${audit.renderedEdges} edges, ${audit.crossings.length} crossings`);
    } catch (error) {
      await page.screenshot({ path: path.join(output, `${key}-FAILED.png`) });
      await fs.writeFile(path.join(output, `${key}-FAILED.txt`), String(error));
      throw error;
    } finally { await page.close(); }
  }
  await fs.writeFile(path.join(output, "rendered-audit.json"), JSON.stringify(results, null, 2));
}
