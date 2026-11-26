import { expect, type Page } from "@playwright/test";
import { auditRenderedGraph, graphGrammarExpression } from "../../scripts/graph-visual-audit.mjs";

export async function assertAgentPathStructure(page: Page) {
  const canvas = page.getByTestId("graph-agent-evidence");
  await expect(canvas).toHaveAttribute("data-layout", "path");
  const spine = ["display:internet", "container:copilot-portal", "agent:developer-copilot", "server:filesystem", "display:scope-findings:server:filesystem"];
  await expect(canvas.locator("[data-internet-anchor]")).toHaveCount(1);
  await expect(canvas.locator('.react-flow__node[data-id="agent:sre-runbook"]')).toHaveCount(0);
  await expect(canvas.getByRole("button", { name: "also used by: SRE Runbook Agent" })).toBeVisible();
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
  await expect.poll(async () => (await page.evaluate(auditRenderedGraph, { edges })).crossings).toEqual([]);
  await expect.poll(async () => ((await page.evaluate(graphGrammarExpression())) as Record<string, string[]>).throughCaptions ?? []).toEqual([]);
}
