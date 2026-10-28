/**
 * Scope captions for look-alike counts that derive from different bases.
 *
 * The Agents page sums configured entries per agent (`GET /v1/agents`), so a
 * server or package declared by several agents counts once per agent. Asset
 * inventory counts each recorded asset once in the latest graph snapshot
 * (`GET /v1/inventory/*`). Both pages read these so the wording stays paired.
 */

export const CONFIGURED_COUNT_SCOPE = {
  caption: "configured",
  title:
    "Configured entries summed across the agents listed here; a server or package declared by several agents counts once per agent. " +
    "Asset inventory counts each recorded asset once in the latest snapshot.",
} as const;

export const SNAPSHOT_COUNT_SCOPE = {
  caption: "in snapshot",
  title:
    "Distinct recorded assets in the latest graph snapshot, each counted once. " +
    "The Agents page sums configured entries per agent, so the same server or package can count there more than once.",
} as const;

/** Joins the scope caption with an optional detail hint, e.g. "configured · 2 remote". */
export function scopedHint(caption: string, detail?: string | null): string {
  return detail ? `${caption} · ${detail}` : caption;
}
