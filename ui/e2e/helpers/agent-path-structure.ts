import { expect, type Page } from "@playwright/test";
import { auditRenderedGraph, graphGrammarExpression } from "../../scripts/graph-visual-audit.mjs";

export async function assertAgentPathStructure(page: Page) {
  const canvas = page.getByTestId("graph-agent-evidence");
  await expect(canvas).toHaveAttribute("data-layout", "path");
  const spine = ["display:internet", "container:copilot-portal", "agent:developer-copilot", "server:filesystem", "display:scope-findings:server:filesystem"];
  await expect(canvas.locator("[data-internet-anchor]")).toHaveCount(1);
  await expect(canvas.locator('.react-flow__node[data-id="agent:sre-runbook"]')).toHaveCount(0);
  await expect(canvas.getByRole("button", { name: "also used by: SRE Runbook Agent" })).toBeVisible();
  expect(await canvas.evaluate(element => {
    const chip = [...element.querySelectorAll("button")].find(button => button.textContent?.startsWith("also used by:"))!.getBoundingClientRect();
    const frame = element.getBoundingClientRect();
    const clipped = chip.left < frame.left || chip.right > frame.right || chip.top < frame.top || chip.bottom > frame.bottom;
    const captions = [...element.querySelectorAll("[data-graph-caption]")].map(caption => caption.getBoundingClientRect());
    const crossed = [...element.querySelectorAll<SVGPathElement>(".react-flow__edge-path")].some(path => {
      const length = path.getTotalLength(), matrix = path.getScreenCTM()!;
      for (let step = 0; step <= length; step += 2) {
        const point = path.getPointAtLength(step).matrixTransform(matrix);
        if (captions.some(box => point.x > box.left && point.x < box.right && point.y > box.top && point.y < box.bottom)) return true;
      }
      return false;
    });
    return { clipped, crossed };
  })).toEqual({ clipped: false, crossed: false });
  const pairs = [...spine.slice(1).map((id, index) => [spine[index]!, id]), ["sa:jit-review", "role:prod-admin"], ["role:prod-admin", "agent:developer-copilot"], ["agent:developer-copilot", "server:github"]];
  const expectedIds = [...new Set(pairs.flat())].sort();
  await expect.poll(() => canvas.locator(".react-flow__node").evaluateAll(nodes => nodes.map(node => node.getAttribute("data-id")!).sort())).toEqual(expectedIds);
  await expect(canvas.locator(".react-flow__edge")).toHaveCount(pairs.length);
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
    const color = index < 4 ? "--graph-edge-exposure" : edge.source === "role:prod-admin" ? "--graph-edge-risk" : "--graph-edge-structure";
    const path = canvas.locator(`[data-id="${edge.id}"] .react-flow__edge-path`);
    expect(await path.evaluate((element, token) => (element as SVGElement).style.stroke === `var(${token})`, color)).toBe(true);
  }
  await expect(canvas.locator(".graph-relationship-label:visible")).toHaveCount(1);
  await expect(canvas.locator(".graph-relationship-label:visible")).toContainText("Can Access");
  const agent = canvas.locator('.react-flow__node[data-id="agent:developer-copilot"]');
  await expect(agent.locator("[data-finding-disclosure]")).toHaveText("1in scope");
  await expect(canvas.locator('.react-flow__node[data-id="server:filesystem"] [data-finding-disclosure]')).toHaveCount(0);
  expect(await agent.evaluate(node => {
    const badge = node.querySelector("[data-finding-disclosure]")!.getBoundingClientRect();
    const name = node.querySelector("[data-semantic-name]")!.getBoundingClientRect();
    return badge.bottom < name.top;
  })).toBe(true);
  for (const id of ["container:copilot-portal", "server:github"]) {
    const name = canvas.locator(`.react-flow__node[data-id="${id}"] [data-semantic-name]`);
    expect(await name.evaluate(node => node.getBoundingClientRect().height)).toBeLessThan(25);
  }
  const incoming = [edges[1]!.id, edges[5]!.id];
  expect(await canvas.evaluate((element, ids) => {
    const ends = ids.map(id => {
      const path = element.querySelector<SVGPathElement>(`[data-id="${CSS.escape(id)}"] .react-flow__edge-path`)!;
      return path.getPointAtLength(path.getTotalLength()).matrixTransform(path.getScreenCTM()!);
    });
    return Math.hypot(ends[0]!.x - ends[1]!.x, ends[0]!.y - ends[1]!.y);
  }, incoming)).toBeGreaterThan(20);
  await expect.poll(async () => (await page.evaluate(auditRenderedGraph, { edges })).crossings).toEqual([]);
  await expect.poll(async () => ((await page.evaluate(graphGrammarExpression())) as Record<string, string[]>).throughCaptions ?? []).toEqual([]);
}
