import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

/**
 * CISO, AppSec and AI-owner journeys against a running demo-estate API: each
 * metric read on two surfaces must agree, or the page must say why it differs.
 *
 * Opt-in like count-consistency-live: start `agent-bom api --demo-estate`, point
 * the UI dev server at it, and run with AGENT_BOM_E2E_LIVE_API=http://127.0.0.1:<port>.
 */
const LIVE_API = process.env.AGENT_BOM_E2E_LIVE_API ?? "";

test.skip(!LIVE_API, "Set AGENT_BOM_E2E_LIVE_API to a demo-estate API the UI dev server reads");
test.describe.configure({ timeout: 240_000 });

type AttackPaths = { attack_paths: { source: string; vuln_ids: string[]; hops: string[] }[]; nodes: { id: string; label: string }[] };
type Counts = { issues: { critical: number; high: number } };

async function liveJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${LIVE_API}${path}`, { timeout: 120_000 });
  expect(response.ok(), path).toBe(true);
  return (await response.json()) as T;
}

async function open(page: Page, path: string) {
  await page.goto(path, { timeout: 120_000 });
  await page.waitForLoadState("networkidle", { timeout: 120_000 }).catch(() => undefined);
}

test("CISO: overview's #1 risk is Investigation's #1 path, and Open investigation lands on the selected risk", async ({ page, request }) => {
  const queue = await liveJson<AttackPaths>(request, "/v1/graph/attack-paths?limit=5");
  const first = queue.attack_paths[0]!;
  const firstCve = first.vuln_ids[0]!;

  await open(page, "/");
  await page.getByRole("tab", { name: "Top risks" }).click();
  await expect(page.getByText(/Same order as Investigation/)).toBeVisible({ timeout: 60_000 });
  const rows = page.getByRole("group", { name: "Select a risk" }).getByRole("button");
  await expect(rows.first()).toContainText(firstCve);

  await rows.nth(1).click();
  const secondCve = ((await rows.nth(1).textContent()) ?? "").match(/CVE-\d{4}-\d+/)?.[0];
  expect(secondCve).toBeTruthy();
  const link = page.getByRole("link", { name: /Open investigation/ });
  await expect(link).toHaveAttribute("href", new RegExp(`cve=${secondCve}`));
  await link.click();
  await expect(page).toHaveURL(new RegExp(`/security-graph\\?.*cve=${secondCve}`));
  await expect(page.getByText(new RegExp(`→ ${secondCve}`)).first()).toBeVisible({ timeout: 120_000 });
});

test("CISO: the trend states its basis whenever it differs from the posture headline", async ({ page, request }) => {
  const { issues } = await liveJson<Counts>(request, "/v1/posture/counts");
  await open(page, "/");
  await page.getByText("Changes over time").click();
  const chart = page.getByRole("figure").filter({ hasText: "vulnerability occurrences in this scan scope" });
  await expect(chart).toBeVisible({ timeout: 60_000 });
  const now = Number(((await chart.locator("p").first().textContent()) ?? "").match(/^\s*([\d,]+)/)?.[1]?.replace(/,/g, "") ?? NaN);
  if (now !== issues.critical) {
    await expect(chart).toContainText(`posture headline counts ${issues.critical.toLocaleString()} critical`);
  }
});

test("AI owner: the agent drawer's per-finding credentials equal the exploit story's", async ({ page, request }) => {
  const detail = await liveJson<{ blast_radius: { vulnerability_id: string; package: string; exposed_credentials: string[] }[] }>(request, "/v1/agents/langchain-service");
  const worst = detail.blast_radius.find((row) => row.vulnerability_id === "CVE-2023-36258")!;
  const [name] = worst.package.split("@");
  const story = await liveJson<{ at_risk: { by_kind: { credentials: number } } }>(
    request, `/v1/graph/exploit-story?node=vuln:${worst.vulnerability_id}&package=pkg:pypi:${worst.package}`,
  );
  expect(story.at_risk.by_kind.credentials).toBe(worst.exposed_credentials.length);

  await open(page, "/agents");
  await page.getByText("LangChain Service").first().click();
  const drawer = page.getByRole("dialog");
  const row = drawer.getByRole("listitem").filter({ hasText: worst.vulnerability_id });
  await expect(row).toContainText(`${worst.exposed_credentials.length} credentials exposed`, { timeout: 60_000 });
  await expect(drawer).toContainText(name!);
});

test("AppSec: a workload-reached finding names its reacher, never 'Agent unavailable'", async ({ page }) => {
  await open(page, "/findings");
  await expect(page.getByRole("button", { name: "Investigate" }).first()).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText("Agent unavailable", { exact: true })).toHaveCount(0);
});
