import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

/**
 * Reads the same metric off every page against a running demo-estate API and
 * asserts one number per metric, or an explicit unit/scope label.
 *
 * Opt-in: start `agent-bom api --demo-estate` and point the UI at it, then run
 * with AGENT_BOM_E2E_LIVE_API=http://127.0.0.1:<port>.
 */
const LIVE_API = process.env.AGENT_BOM_E2E_LIVE_API ?? "";

test.skip(!LIVE_API, "Set AGENT_BOM_E2E_LIVE_API to a demo-estate API the UI dev server reads");
test.describe.configure({ timeout: 180_000 });

type IssueCounts = { critical: number; high: number; medium: number; total: number; kev: number };

async function liveJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${LIVE_API}${path}`, { timeout: 120_000 });
  expect(response.ok(), path).toBe(true);
  return (await response.json()) as T;
}

function number(text: string): number {
  return Number(text.replace(/[^\d]/g, ""));
}

async function open(page: Page, path: string) {
  await page.goto(path, { timeout: 120_000 });
  await page.waitForLoadState("networkidle", { timeout: 120_000 }).catch(() => undefined);
}

test("critical, high, medium and KEV issues read the same on overview, nav and findings", async ({ page, request }) => {
  const { issues } = await liveJson<{ issues: IssueCounts }>(request, "/v1/posture/counts");

  await open(page, "/");
  for (const [label, value] of [["Critical", issues.critical], ["High", issues.high], ["Medium", issues.medium]] as const) {
    await expect(page.getByRole("link", { name: new RegExp(`^${label} ${value.toLocaleString()}`, "i") }).first()).toBeVisible();
  }
  const kev = page.getByRole("link", { name: new RegExp(`^KEV ${issues.kev}$`) });
  await expect(kev).toBeVisible();
  await expect(kev).toHaveAttribute("title", /known-exploited issue/);

  await open(page, "/findings?lane=all");
  await expect(page.getByRole("tab", { name: `All findings ${issues.total.toLocaleString()}` })).toBeVisible({ timeout: 120_000 });
  for (const [label, value] of [["Critical", issues.critical], ["High", issues.high], ["Medium", issues.medium]] as const) {
    await expect(page.getByRole("button", { name: `${label} (${value})` })).toBeVisible({ timeout: 60_000 });
  }
});

test("occurrence and scope totals carry their unit", async ({ page, request }) => {
  const counts = await liveJson<{ agents: { total: number } }>(request, "/v1/posture/counts");
  const host = await liveJson<{ count: number; scope: string }>(request, "/v1/agents");

  await open(page, "/");
  await page.getByRole("tab", { name: "Assets & coverage" }).click().catch(() => undefined);
  await expect(page.getByText(/Counts are finding occurrences, not issues/).first()).toBeVisible();

  await open(page, "/agents");
  const kpis = page.getByTestId("agents-kpis");
  if (host.scope === "local_discovery") {
    await expect(kpis.getByText("Agents on this host")).toBeVisible();
    await expect(kpis.getByText(`${counts.agents.total.toLocaleString()} in the estate`)).toBeVisible();
  }
});

test("unique credentials match the posture dimension", async ({ page, request }) => {
  const posture = await liveJson<{ dimensions: { credential_hygiene: { details: string } } }>(request, "/v1/posture");
  const expected = number(posture.dimensions.credential_hygiene.details.split(" unique")[0] ?? "");

  await open(page, "/agents");
  const tile = page.getByTestId("agents-kpis").getByText("Unique credentials").locator("xpath=ancestor::*[2]");
  await expect(tile).toContainText(String(expected));
});

test("frameworks covered and NIST 800-53 pass/fail read the same on overview and compliance", async ({ page }) => {
  await open(page, "/");
  const coverage = page.getByText(/\d+ control frameworks · \d+ risk mappings/).first();
  await expect(coverage).toBeVisible();
  const [controlFrameworks] = ((await coverage.textContent()) ?? "").match(/\d+/) ?? ["0"];

  await open(page, "/compliance");
  const tile = page.getByText("Control frameworks", { exact: true }).locator("xpath=ancestor::*[2]");
  await expect(tile).toContainText(controlFrameworks);

  const row = page.getByRole("cell", { name: /NIST SP 800-53/ }).first().locator("xpath=ancestor::tr[1]");
  await expect(row).toContainText(/evaluated pass/, { timeout: 60_000 });
  const rowText = (await row.getByText(/evaluated pass/).first().textContent()) ?? "";
  const [passed, evaluated] = (rowText.match(/^\s*(\d+)\/(\d+) evaluated pass/) ?? []).slice(1);
  await expect(page.getByTestId("nist-mapped-summary")).toContainText(`${passed}/${evaluated} evaluated controls pass`);
});

test("remediation names its read window", async ({ page }) => {
  await open(page, "/remediation");
  await expect(page.getByText(/packages prioritized by reach, severity, and available fixes · Last \d+ days/)).toBeVisible();
});
