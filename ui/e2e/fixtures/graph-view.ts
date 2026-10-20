import type { Page } from "@playwright/test";

/**
 * A phone opens a loaded graph on its readable list (paths or connections);
 * the canvas is one tap away. Specs that drive the canvas open it first.
 * No-op at desktop widths, where the canvas is the default.
 */
export async function openGraphView(page: Page): Promise<void> {
  if ((page.viewportSize()?.width ?? 1440) >= 640) return;
  const toggle = page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true });
  const shown = await toggle.waitFor({ state: "visible", timeout: 10_000 }).then(() => true, () => false);
  if (shown && (await toggle.getAttribute("aria-pressed")) !== "true") await toggle.click();
}
