"use client";

import { useEffect, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";

/** Seconds a busy view waits before it retries its read on its own. */
export const BUSY_AUTO_RETRY_SECONDS = 15;

/** A live "retrying in Ns" line that calls `onRetry` when the countdown ends, or on demand. */
export function BusyRetryCountdown({ onRetry, seconds = BUSY_AUTO_RETRY_SECONDS }: { onRetry: () => void; seconds?: number }) {
  const [remaining, setRemaining] = useState(seconds);
  const retry = useRef(onRetry);
  useEffect(() => { retry.current = onRetry; }, [onRetry]);
  useEffect(() => {
    const tick = setInterval(() => setRemaining((value) => Math.max(0, value - 1)), 1000);
    const fire = setTimeout(() => retry.current(), seconds * 1000);
    return () => {
      clearInterval(tick);
      clearTimeout(fire);
    };
  }, [seconds]);
  return (
    <p role="status" aria-live="polite" className="mt-3 inline-flex items-center gap-2 text-xs text-[var(--text-secondary)]">
      <span>{remaining > 0 ? `Retrying in ${remaining}s` : "Retrying…"}</span>
      <button
        type="button"
        onClick={() => retry.current()}
        className="inline-flex items-center gap-1 rounded-md border border-[var(--border-subtle)] px-2 py-0.5 text-[var(--foreground)] hover:bg-[var(--surface-muted)]"
      >
        <RefreshCw className="h-3 w-3" aria-hidden="true" />
        Retry now
      </button>
    </p>
  );
}
