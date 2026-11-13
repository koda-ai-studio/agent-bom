/** True when the reader asked for no motion, or when that cannot be known (no window or matchMedia). */
export function prefersReducedMotion(): boolean {
  return typeof window === "undefined" || typeof window.matchMedia !== "function" || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
