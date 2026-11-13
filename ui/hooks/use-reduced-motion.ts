"use client";

import { useSyncExternalStore } from "react";

const QUERY = "(prefers-reduced-motion: reduce)";

function subscribe(onChange: () => void) {
  const media = typeof window !== "undefined" ? window.matchMedia?.(QUERY) : undefined;
  media?.addEventListener?.("change", onChange);
  return () => media?.removeEventListener?.("change", onChange);
}

/** True when the reader asked for no motion, or when that cannot be known (server render, no matchMedia). */
export function useReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => typeof window.matchMedia !== "function" || window.matchMedia(QUERY).matches,
    () => true,
  );
}
