/**
 * Viewport height that ends just below the content, never shorter than `min`.
 * It never grows past `max`, which defaults to the current height, so a capture
 * only grows when its caller sets a taller ceiling for content longer than the viewport.
 */
export function fittedViewportHeight(contentBottom, currentHeight, { min = 480, pad = 32, max = currentHeight } = {}) {
  if (!Number.isFinite(contentBottom) || contentBottom <= 0) return currentHeight;
  return Math.min(Math.max(currentHeight, max), Math.max(min, Math.ceil(contentBottom + pad)));
}

/** The next wider capture viewport while a canvas still reports nodes off screen, or null at the ceiling. */
export function nextCaptureWidth(currentWidth, { step = 160, max = 2400 } = {}) {
  if (currentWidth >= max) return null;
  return Math.min(max, currentWidth + step);
}

const settle = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));

/** Fit the viewport to the bottom of `selector`'s last visible match: shrink a short page, grow a long one up to `max`. */
export async function fitViewportToContent(page, { selector, min, pad, max }) {
  const bottom = await page.locator(selector).evaluateAll(elements => Math.max(0, ...elements
    .map(element => element.getBoundingClientRect())
    .filter(rect => rect.width > 0 && rect.height > 0)
    .map(rect => rect.bottom + window.scrollY)));
  const viewport = page.viewportSize();
  const height = fittedViewportHeight(bottom, viewport.height, { min, pad, max });
  if (height === viewport.height) return;
  await page.setViewportSize({ width: viewport.width, height });
  await settle(page);
}

export const OFFSCREEN_NODES_TEXT = /\d+ more nodes? off screen/;

/** Widen the viewport until the graph camera frames every node; fail rather than capture a clipped graph. */
export async function widenUntilNoNodesOffscreen(page, { step, max, settleMs = 300 } = {}) {
  const indicator = page.getByText(OFFSCREEN_NODES_TEXT);
  for (;;) {
    await settle(page);
    await page.waitForTimeout(settleMs);
    if (!(await indicator.isVisible())) return page.viewportSize();
    const viewport = page.viewportSize();
    const width = nextCaptureWidth(viewport.width, { step, max });
    if (width === null) throw new Error(`Graph still has nodes off screen at a ${viewport.width}px capture width`);
    await page.setViewportSize({ width, height: viewport.height });
  }
}
