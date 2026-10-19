"use client";

import { useEffect, useState } from "react";

/** Phone-width breakpoint shared by the embedded path graph's layout and toolbar. */
export const NARROW_VIEWPORT_QUERY = "(max-width: 639px)";

export function useNarrowViewport(enabled = true): boolean {
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    if (!enabled || typeof window.matchMedia !== "function") return;
    const media = window.matchMedia(NARROW_VIEWPORT_QUERY);
    const update = () => setNarrow(media.matches);
    update();
    media.addEventListener?.("change", update);
    return () => media.removeEventListener?.("change", update);
  }, [enabled]);
  return enabled && narrow;
}
