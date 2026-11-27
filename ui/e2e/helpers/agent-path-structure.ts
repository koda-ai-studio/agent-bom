import { expect, type Page } from "@playwright/test";
import { auditRenderedGraph, graphGrammarExpression } from "../../scripts/graph-visual-audit.mjs";

export async function assertAgentPathStructure(page: Page) {
  const canvas = page.getByTestId("graph-agent-evidence");
  await expect(canvas).toHaveAttribute("data-layout", "path");
  await expect(canvas.locator("[data-recorded-boundary]")).toHaveCount(0);
  await expect(page.locator("[data-scope-breadcrumb]")).toHaveText("AWS prod account");
  await expect.poll(async () => {
    const github = (await canvas.locator('.react-flow__node[data-id="server:github"]').boundingBox())!;
    const filesystem = (await canvas.locator('.react-flow__node[data-id="server:filesystem"]').boundingBox())!;
    return Math.abs(github.x - filesystem.x) < 1 && github.y > filesystem.y + filesystem.height;
  }).toBe(true);
  const spine = ["display:internet", "container:copilot-portal", "agent:developer-copilot", "server:filesystem", "cred:aws", "store:ai-training"];
  await expect(canvas.locator("[data-internet-anchor]")).toHaveCount(1);
  await expect(canvas.locator('.react-flow__node[data-id="agent:sre-runbook"]')).toHaveCount(0);
  await expect(canvas.getByRole("button", { name: "also used by: SRE Runbook Agent" })).toBeVisible();
  const pairs = [...spine.slice(1).map((id, index) => [spine[index]!, id]), ["server:filesystem", "tool:exec"], ["server:filesystem", "display:scope-findings:server:filesystem"], ["agent:developer-copilot", "server:github"], ["container:copilot-portal", "display:scope-findings:container:copilot-portal"]];
  const expectedIds = [...new Set(pairs.flat())].sort();
  await expect.poll(() => canvas.locator(".react-flow__node").evaluateAll(nodes => nodes.map(node => node.getAttribute("data-id")!).sort())).toEqual(expectedIds);
  await expect(canvas.locator(".react-flow__edge")).toHaveCount(pairs.length);
  await expect.poll(() => canvas.evaluate(auditAgentCaptions)).toEqual({ clipped: false, crossed: [] });
  const original = await canvas.locator(".react-flow__edge").evaluateAll(edges => edges.map(edge => edge.getAttribute("data-id")!));
  const edges = pairs.map(([source, target]) => {
    const id = original.find(id => source === "display:internet" ? id === `${source}:${target}` : target!.startsWith("display:scope-findings:") ? id === `${target}:disclosure` : source === "container:copilot-portal" ? id === `${target}->${source}:hosted_on` : id.startsWith(`${source}->${target}:`));
    expect(id, `recorded connection ${source} → ${target}`).toBeDefined();
    return { id: id!, source: source!, target: target! };
  });
  const visited = new Set([spine[0]]);
  for (let i = 0; i < expectedIds.length; i++) for (const edge of edges) {
    if (visited.has(edge.source) || visited.has(edge.target)) { visited.add(edge.source); visited.add(edge.target); }
  }
  expect([...visited].sort()).toEqual(expectedIds);
  await expect.poll(async () => {
    const bounds = await canvas.locator(".react-flow__node").evaluateAll(nodes => Object.fromEntries(nodes.map(node => [node.getAttribute("data-id"), node.getBoundingClientRect().x])));
    return pairs.every(([source, target]) => bounds[source!] < bounds[target!]);
  }).toBe(true);
  for (const [index, edge] of edges.entries()) {
    const color = index < 6 ? "--graph-edge-exposure" : edge.source === "role:prod-admin" ? "--graph-edge-risk" : "--graph-edge-structure";
    const path = canvas.locator(`[data-id="${edge.id}"] .react-flow__edge-path`);
    expect(await path.evaluate((element, token) => (element as SVGElement).style.stroke === `var(${token})`, color)).toBe(true);
  }
  const contextLine = canvas.locator(`[data-id="${edges[0]!.id}"] .react-flow__edge-path`);
  await expect(contextLine).toHaveAttribute("marker-end", /.+/);
  await expect(contextLine).toHaveCSS("stroke-dasharray", "none");
  for (const path of await canvas.locator('.react-flow__edge-path[marker-end]').all()) {
    const width = await path.evaluate(element => {
      const id = element.getAttribute("marker-end")!.replace(/^url\(['"]?#/, "").replace(/['"]?\)$/, "");
      const marker = document.getElementById(id) as unknown as SVGMarkerElement;
      const shape = marker.querySelector<SVGGraphicsElement>("polyline")!;
      return shape.getBBox().width / marker.viewBox.baseVal.width * marker.markerWidth.baseVal.value * (element as SVGPathElement).getScreenCTM()!.a * (marker.markerUnits.baseVal === 2 ? Number.parseFloat(getComputedStyle(element).strokeWidth) : 1);
    });
    expect(width).toBeGreaterThanOrEqual(4);
    expect(width).toBeLessThanOrEqual(9);
  }
  await expect(canvas.locator(".graph-relationship-label:visible")).toHaveCount(0);
  await expect(canvas.locator('[data-id="role:prod-admin"]')).toHaveCount(0);
  await expect(canvas.getByRole("button", {name: "admin via prod-ai-admin"})).toBeVisible();
  for (const owner of ["container:copilot-portal", "server:filesystem"]) {
    const asset = canvas.locator(`.react-flow__node[data-id="${owner}"]`);
    const group = canvas.locator(`.react-flow__node[data-id="display:scope-findings:${owner}"]`);
    await expect(asset.locator("[data-finding-disclosure]")).toHaveCount(0);
    const a = (await asset.boundingBox())!, g = (await group.boundingBox())!;
    expect(g.y).toBeLessThan(a.y);
    const hop = (await canvas.locator('.react-flow__node[data-id="server:filesystem"]').boundingBox())!.x - (await canvas.locator('.react-flow__node[data-id="agent:developer-copilot"]').boundingBox())!.x;
    expect(g.x - a.x).toBeLessThanOrEqual(hop / 2 + 1);
  }
  await expect(canvas.locator('[data-id="store:ai-training"] [data-compact-marker="sensitive"]')).toHaveAttribute("aria-label", /Recorded critical asset · data classification: confidential/);
  await expect(canvas.locator('[data-id="cred:aws"] [data-compact-marker]')).toHaveCount(0);
  await expect(canvas.locator('[data-id="store:ai-training"] .graph-provider-mark-node')).toHaveCount(0);
  for (const edge of edges.slice(0, 6)) expect(await canvas.locator(`[data-id="${edge.id}"] .react-flow__edge-path`).evaluate(element => (element as SVGElement).style.strokeDasharray)).toBe("");
  for (const id of ["container:copilot-portal", "server:github"]) {
    const name = canvas.locator(`.react-flow__node[data-id="${id}"] [data-semantic-name]`);
    expect(await name.evaluate(node => node.getBoundingClientRect().height)).toBeLessThan(25);
  }
  await expect.poll(async () => (await page.evaluate(auditRenderedGraph, { edges })).crossings).toEqual([]);
  await expect.poll(async () => ((await page.evaluate(graphGrammarExpression())) as Record<string, string[]>).throughCaptions ?? []).toEqual([]);
}

export function auditAgentCaptions(element: HTMLElement) {
    const chip = [...element.querySelectorAll("button")].find(button => button.textContent?.startsWith("also used by:"))!.getBoundingClientRect();
    const frame = element.getBoundingClientRect();
    const clipped = chip.left < frame.left || chip.right > frame.right || chip.top < frame.top || chip.bottom > frame.bottom;
    const captions = [...element.querySelectorAll("[data-graph-caption], [data-semantic-name]")].map(caption => ({box: caption.getBoundingClientRect(), label: caption.textContent}));
    const crossed = [...element.querySelectorAll<SVGPathElement>(".react-flow__edge-path")].flatMap(path => {
      const length = path.getTotalLength(), matrix = path.getScreenCTM()!;
      for (let step = 0; step <= length; step += 2) {
        const point = path.getPointAtLength(step).matrixTransform(matrix);
        const hit = captions.find(({box}) => point.x > box.left && point.x < box.right && point.y > box.top && point.y < box.bottom);
        if (hit) return [`${path.closest("[data-id]")?.getAttribute("data-id")} crosses ${hit.label}`];
      }
      return [];
    });
    return { clipped, crossed };
}
