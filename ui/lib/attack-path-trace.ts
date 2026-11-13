/** The whole entry-to-target trace, start to finish. It runs once per selected path and never loops. */
export const PATH_TRACE_MS = 300;

export type HopTrace = { delay: number; duration: number };

/** Each hop draws in turn, so the trace reads as one stroke from the entry to the target. */
export function pathTraceTiming(hops: number, total = PATH_TRACE_MS): HopTrace[] {
  if (hops <= 0) return [];
  const duration = total / hops;
  return Array.from({ length: hops }, (_, index) => ({ delay: Math.round(index * duration), duration: Math.floor(duration) }));
}
