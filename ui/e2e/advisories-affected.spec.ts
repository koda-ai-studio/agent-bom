import { readFileSync } from "node:fs";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

const php2shell = JSON.parse(readFileSync(path.join(__dirname, "..", "tests", "fixtures", "php2shell-affected.json"), "utf8"));

async function baseline(page: Page, theme: string) {
  await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
  await page.route("**/v1/**", (route) => route.fulfill({ json: {} }));
  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/version", (route) => route.fulfill({ json: { version: "0.110.0" } }));
  await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
    authenticated: true, auth_required: false, configured_modes: [], recommended_ui_mode: "no_auth",
    role: "admin", subject: null, auth_method: null, memberships: [], tenant_id: "fixture",
    role_summary: { role: "admin", ui_role: "admin", display_name: "Admin", capabilities: ["policy.manage"] },
  } }));
  await page.route("**/v1/intel/advisories/*/affected?**", (route) => route.fulfill({ json: php2shell }));
  await page.route("**/v1/intel/operator-advisories", (route) => route.request().method() === "POST"
    ? route.fulfill({ status: 422, json: { detail: [{ loc: ["body", "affected", 0], msg: "Value error, introduced must precede fixed", type: "value_error" }] } })
    : route.fulfill({ json: {
      advisories: [{ id: "CVE-2026-109618", aliases: ["CVE-2026-109619"], summary: php2shell.advisory.summary, severity: "critical", references: [], affected: [{ cpe_product: "php:php", ranges: [], versions: [] }], updated_at: "2026-10-23T09:00:00+00:00" }],
      provenance: "operator_advisory",
      rematch: { last_run: "2026-10-24T01:00:00+00:00" },
    } }));
}

async function noPageOverflow(page: Page) {
  await expect(page.locator("#main-content")).toHaveCSS("padding-left", "0px");
  await expect.poll(() => page.evaluate(() => document.querySelector("#main-content")!.getBoundingClientRect().left)).toBeLessThanOrEqual(1);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
}

for (const theme of ["light", "dark"]) {
  test(`advisory affected assets render the PHP2Shell answer in ${theme}`, async ({ page }, testInfo) => {
    await baseline(page, theme);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/advisories?id=CVE-2026-109618");
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const table = page.getByRole("table", { name: "Affected assets" });
    await expect(table).toBeVisible();
    await expect(page.getByRole("list", { name: "Verdict summary" }).getByRole("listitem")).toHaveText([
      "1Affected", "1Possibly affected (distro)", "1Not affected", "1Clean scanned",
    ]);
    await expect(table.getByText("Possibly affected — verify distro advisory")).toBeVisible();
    await expect(table.getByRole("link", { name: "Blast radius for php 8.3.30 on php:8.3.30-cli" }))
      .toHaveAttribute("href", /\/security-graph\?lens=attack-path&scan=scan-php-8\.3\.30&node=pkg%3Ageneric%3Aphp%408\.3\.30/);
    for (const width of [1440, 1280, 390]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
      if (width === 390) await noPageOverflow(page);
      await page.getByTestId("affected-assets").scrollIntoViewIfNeeded();
      await page.screenshot({ path: testInfo.outputPath(`advisories-affected-${theme}-${width}.png`) });
    }

    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/advisories?tab=declare");
    await expect(page.getByRole("listitem", { name: "CVE-2026-109618" })).toBeVisible();
    await page.getByLabel("Advisory ID").fill("CVE-2026-109618");
    await page.getByLabel("Summary").fill("php2shell");
    await page.getByRole("radio", { name: "CPE product" }).check();
    await page.getByLabel("CPE product (vendor:product)").fill("php:php");
    await page.getByLabel("Introduced").fill("8.3.36");
    await page.getByLabel("Fixed").fill("8.3.0");
    await page.getByRole("button", { name: "Declare advisory" }).click();
    await expect(page.getByRole("alert", { name: "The server rejected this advisory" })).toContainText("Affected product 1: introduced must precede fixed");
    for (const width of [1440, 1280, 390]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
      if (width === 390) await noPageOverflow(page);
      await page.screenshot({ path: testInfo.outputPath(`advisories-declare-${theme}-${width}.png`) });
    }
  });
}

/** Every verdict and patch target must sit inside the viewport, and no region may scroll sideways. */
async function answerFitsViewport(page: Page) {
  const overflow = await page.evaluate(() => {
    const region = document.querySelector('[data-testid="affected-assets"]');
    const scrolling = region
      ? [region, ...Array.from(region.querySelectorAll("*"))].filter((el) => el.scrollWidth > el.clientWidth + 1 && ["auto", "scroll"].includes(getComputedStyle(el).overflowX))
      : [];
    return { page: document.documentElement.scrollWidth - window.innerWidth, scrollingRegions: scrolling.length };
  });
  expect(overflow).toEqual({ page: 0, scrollingRegions: 0 });
  const width = page.viewportSize()!.width;
  for (const row of php2shell.rows) {
    const card = page.getByTestId("affected-asset-card").filter({ hasText: row.asset_label });
    await expect(card).toHaveCount(1);
    await expect(card).toContainText(row.verdict === "possibly_affected" ? "Possibly affected — verify distro advisory" : row.verdict === "affected" ? "Affected" : "Not affected");
    for (const target of [card.getByTestId("verdict-badge"), card.getByTestId("patch-target")]) {
      await expect(target).toBeVisible();
      const box = (await target.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(width);
    }
  }
}

test("at 390px each affected asset is a card with its verdict and patch target on screen", async ({ page }) => {
  await baseline(page, "dark");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/advisories?id=CVE-2026-109618");
  await expect(page.getByTestId("affected-assets")).toBeVisible();
  await answerFitsViewport(page);
});

for (const width of [1280, 1440]) {
  test(`at ${width}px the blast-radius action sits fully inside the table container`, async ({ page }) => {
    await baseline(page, "light");
    await page.setViewportSize({ width, height: 1000 });
    await page.goto("/advisories?id=CVE-2026-109618");
    const table = page.getByRole("table", { name: "Affected assets" });
    await expect(table).toBeVisible();
    const container = (await page.getByTestId("affected-assets").boundingBox())!;
    const scroll = await page.getByTestId("affected-assets").evaluate((el) => el.scrollWidth - el.clientWidth);
    expect(scroll).toBeLessThanOrEqual(0);
    for (const link of await table.getByRole("link", { name: /^Blast radius for / }).all()) {
      const box = (await link.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(container.x);
      expect(box.x + box.width).toBeLessThanOrEqual(container.x + container.width);
    }
  });
}

for (const theme of ["light", "dark"]) {
  test(`unnamed package occurrences keep readable labels and exact evidence in ${theme}`, async ({ page }, testInfo) => {
    await baseline(page, theme);
    const node = "pkg:pypi:pillow@9.0.0:image:00fcd6ed33ef";
    const row = { ...php2shell.rows[0], asset: { agent: "", server: "", node_id: node },
      asset_label: node, asset_type: "package", asset_node_id: node,
      package: { name: "pillow", version: "9.0.0", ecosystem: "pypi" }, installed_version: "9.0.0",
      graph: { package_node_id: node, server_node_id: null, agent_node_id: null } };
    await page.route("**/v1/intel/advisories/*/affected?**", route => route.fulfill({ json: {
      ...php2shell, rows: [row], count: 1,
      summary: { affected: 1, possibly_affected: 0, not_affected: 0, clean_scanned: 0, assets_examined: 1, reports_examined: 1 },
    } }));
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.goto("/advisories?id=CVE-2026-109618");
      const surface = width === 390 ? page.getByTestId("affected-asset-card").first()
        : page.getByRole("table", { name: "Affected assets" }).getByRole("row").nth(1);
      await expect(surface.getByText("pillow@9.0.0", { exact: true })).toBeVisible();
      await expect(surface.getByText("Package occurrence · owner not recorded")).toBeVisible();
      await expect(surface.getByText(node, { exact: true })).toBeHidden();
      await surface.locator("summary").filter({ hasText: "Evidence identity" }).click();
      await expect(surface.getByText(node, { exact: true })).toBeVisible();
      await expect(surface.getByRole("link")).toHaveAttribute("href", new RegExp(`node=${encodeURIComponent(node)}`));
      expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)).toBe(false);
      await page.screenshot({ path: testInfo.outputPath(`occurrence-identity-${theme}-${width}.png`), fullPage: true });
    }
  });
}
