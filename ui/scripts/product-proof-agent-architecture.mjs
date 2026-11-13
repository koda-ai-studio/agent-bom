// Product-proof capture of the agent architecture view. The fixture is the
// backend read path's answer for the repository's framework fixtures (see
// tests/fixtures/agent-architecture-fixture.ts); nothing here is hand-written.
import fs from "node:fs/promises";
import path from "node:path";

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const ROUTE = "/v1/graph/agent-architecture";
const PAGE = "/agents/architecture?capture=1";
const fixture = JSON.parse(await fs.readFile(path.join(UI_ROOT, "tests/fixtures/agent-architecture.json"), "utf8"));

export const AGENT_ARCHITECTURE_SCREENSHOTS = [
  { path: "agent-architecture-layered-dark-live.png", page: PAGE, presentation: "dark desktop",
    scope: "LangGraph supervisor harness declared in source, drawn by layer with an unresolved route stub and a synthetic finding badge" },
  { path: "agent-architecture-flow-light-live.png", page: PAGE, presentation: "light desktop",
    scope: "The same harness as a flow from entry to finish; returns are markers, observed paths are stated as not available" },
  { path: "agent-architecture-mobile-live.png", page: PAGE, presentation: "dark mobile",
    scope: "The harness as a single column of layers at a 390 by 844 viewport" },
];

export async function installAgentArchitectureRoutes(page) {
  await page.route((url) => url.pathname === ROUTE, (route) => {
    const cursor = new URL(route.request().url()).searchParams.get("cursor");
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(cursor ? fixture.second_page : fixture.first_page) });
  });
}

const assertions = {
  expectedText: ["Agent architecture", "supervisor", "1 unresolved route", "Observed runtime paths are not available yet"],
  rejectedText: [/Loading agent architecture/i],
  expectedApiPaths: [ROUTE],
};

/** Layered (dark), flow (light) and phone (dark) captures through the shared capture helper. */
export async function captureAgentArchitecture({ capture, newCapturePage }) {
  const ready = async (target) => target.getByRole("heading", { name: "Agent architecture", level: 1 }).waitFor({ state: "visible", timeout: 20_000 });
  const darkPage = await newCapturePage("dark", { width: 1440, height: 980 });
  await capture(darkPage, PAGE, "agent-architecture-layered-dark-live.png", async (target) => {
    await ready(target);
    await target.getByTestId("architecture-canvas").locator(".react-flow__node").first().waitFor({ state: "visible", timeout: 20_000 });
    await target.waitForTimeout(400);
  }, { ...assertions, minGraphNodes: 9, maxGraphNodes: 9, minGraphEdges: 8, maxGraphEdges: 8 });
  await darkPage.close();

  const lightPage = await newCapturePage("light", { width: 1440, height: 980 });
  await capture(lightPage, PAGE, "agent-architecture-flow-light-live.png", async (target) => {
    await ready(target);
    await target.getByRole("button", { name: "Flow", exact: true }).click();
    await target.locator('[data-testid="architecture-canvas"][data-layout="flow"] .react-flow__node').first().waitFor({ state: "visible", timeout: 20_000 });
    await target.waitForTimeout(400);
  }, { ...assertions, expectedText: [...assertions.expectedText, "End of research_builder"], minGraphNodes: 11, maxGraphNodes: 11, minGraphEdges: 11, maxGraphEdges: 11 });
  await lightPage.close();

  const mobilePage = await newCapturePage("dark", { width: 390, height: 844 });
  await capture(mobilePage, PAGE, "agent-architecture-mobile-live.png", async (target) => {
    await ready(target);
    await target.getByRole("region", { name: "Harness layers" }).waitFor({ state: "visible", timeout: 20_000 });
  }, { ...assertions, assertNoHorizontalOverflow: true });
  await mobilePage.close();
}
