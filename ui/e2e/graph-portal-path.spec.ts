import { expect, test } from "@playwright/test";
import { installAgentScopeFixture } from "./helpers/agent-scope-fixture";
import { attackPathKey } from "../lib/attack-paths";

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) test(`Find a path offers the exposed portal CVE route ${theme} ${width}`, async ({page}, info) => {
  await page.setViewportSize({width, height: 1000});
  await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
  const {graph, errors} = await installAgentScopeFixture(page);
  const route = graph.attack_paths.find((path: {source: string}) => path.source === "container:copilot-portal");
  expect(route).toBeDefined();
  await page.goto(`/security-graph?scan=${graph.scan_id}&selected_path=${encodeURIComponent(attackPathKey(route))}`);
  const canvas = page.getByTestId("attack-path-graph-canvas");
  await expect(canvas).toBeVisible();
  await expect(page.getByText("Ranked paths are ready; fix guidance is temporarily unavailable.", {exact: true})).toHaveCount(0);
  for (const label of ["Internet", "copilot-portal:2.4.0", "next@15.2.2", "CVE-2025-29927", "Developer Copilot"])
    await expect(canvas.getByText(label, {exact: true}).first()).toBeVisible();
  await expect(canvas.getByText("prod-ai-admin", {exact: true})).toHaveCount(0);
  await expect(canvas.getByText("Not a hop", {exact: true})).toHaveCount(0);
  await expect(page.getByText(/Internet exposure source: recorded internet_exposed flag on/)).toBeVisible();
  await expect(canvas.locator('[data-recorded-boundary]')).toHaveCount(0);
  await expect(page.locator('[data-scope-breadcrumb]')).toHaveText("AWS prod account › prod-ai-control-plane › eks-ai-runtime");
  await expect(page.getByText("2/2 relationships have source evidence", {exact: true})).toBeVisible();
  await expect(page.getByText("Full-path assessment: not recorded")).toBeVisible();
  await expect(page.getByText(/0 agents on this path/)).toHaveCount(0);
  await expect(canvas.locator('[data-node-badge="findings"]')).toHaveCount(0);
  await expect(canvas.locator('marker[markerUnits="userSpaceOnUse"]')).toHaveCount(4);
  await expect(canvas.getByText("CVE-2025-29927", {exact: true})).toHaveCount(1);
  await page.screenshot({path: info.outputPath(`portal-cve-${theme}-${width}.png`), fullPage: false});
  expect(errors).toEqual([]);
});
