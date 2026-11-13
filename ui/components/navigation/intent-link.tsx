"use client";

import Link from "next/link";
import { useState, type ComponentProps } from "react";

/**
 * App-shell links sit on every page. Prefetching each visible one on load
 * downloads and evaluates other routes' code while the current page paints, so
 * they prefetch on hover, focus or touch instead (the Next.js hover-prefetch
 * pattern, extended so keyboard and touch users get the same head start).
 */
export function IntentLink({ onMouseEnter, onFocus, onTouchStart, prefetch, ...props }: ComponentProps<typeof Link>) {
  const [intent, setIntent] = useState(false);
  return (
    <Link
      {...props}
      prefetch={intent ? (prefetch ?? null) : false}
      onMouseEnter={event => { setIntent(true); onMouseEnter?.(event); }}
      onFocus={event => { setIntent(true); onFocus?.(event); }}
      onTouchStart={event => { setIntent(true); onTouchStart?.(event); }}
    />
  );
}
