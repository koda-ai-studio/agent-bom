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

/**
 * The three agent populations the UI shows. They differ by design and are never
 * reconciled to one number, so every surface names the one it carries.
 */
export const AGENT_COUNT_SCOPE = {
  snapshot: {
    caption: "agent records in snapshot",
    title:
      "Agent records in the latest graph snapshot, each counted once: AI clients, background agents and cloud-managed agents " +
      "(for example Bedrock or Vertex AI). Overview and the posture counts use this number. The Agents page lists the agents " +
      "found by scans or on this host; the Asset inventory AI entities card also counts models, frameworks and datasets.",
  },
  scanned: {
    label: "Scanned agents",
    title:
      "Distinct agent identities in this workspace's completed scans, one per canonical agent, latest scan wins. " +
      "Scanned repositories, SBOMs and images are inventory, not agents; Asset inventory lists them.",
  },
  host: {
    label: "Agents on this host",
    title: "AI-client and background agent configs discovered live on this API host.",
  },
} as const;

/**
 * The two package populations. The Agents page sums the packages each agent's servers declare, so a package
 * several agents use counts once per agent; Overview and Asset inventory count each package record in the
 * snapshot once. Neither is reconciled to the other, so every surface says which one it shows.
 */
export const PACKAGE_COUNT_SCOPE = {
  references: {
    label: "Package references",
    caption: "across agents",
    title:
      "Packages declared by each listed agent's servers, summed per agent: a package several agents use counts once per agent. " +
      "Overview and Asset inventory count unique packages in the latest snapshot.",
  },
  unique: {
    label: "Unique packages",
    title:
      "Distinct package records in the latest graph snapshot, each counted once. " +
      "The Agents page counts package references, one per agent that declares the package.",
  },
} as const;

/** Joins the scope caption with an optional detail hint, e.g. "configured · 2 remote". */
export function scopedHint(caption: string, detail?: string | null): string {
  return detail ? `${caption} · ${detail}` : caption;
}
