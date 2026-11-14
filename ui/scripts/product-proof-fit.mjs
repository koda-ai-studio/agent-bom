/** Viewport height that ends just below the content, never taller than the current viewport or shorter than `min`. */
export function fittedViewportHeight(contentBottom, currentHeight, { min = 480, pad = 32 } = {}) {
  if (!Number.isFinite(contentBottom) || contentBottom <= 0) return currentHeight;
  return Math.min(currentHeight, Math.max(min, Math.ceil(contentBottom + pad)));
}

/** Shrink the viewport to the bottom of `selector`'s last visible match, so a short page leaves no empty half. */
export async function fitViewportToContent(page, { selector, min, pad }) {
  const bottom = await page.locator(selector).evaluateAll(elements => Math.max(0, ...elements
    .map(element => element.getBoundingClientRect())
    .filter(rect => rect.width > 0 && rect.height > 0)
    .map(rect => rect.bottom + window.scrollY)));
  const viewport = page.viewportSize();
  const height = fittedViewportHeight(bottom, viewport.height, { min, pad });
  if (height === viewport.height) return;
  await page.setViewportSize({ width: viewport.width, height });
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}
