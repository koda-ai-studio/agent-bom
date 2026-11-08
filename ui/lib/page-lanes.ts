export type PageLane =
  | "command"
  | "ai-estate"
  | "cloud-data"
  | "runtime"
  | "governance"
  | "reference"
  | "operations";

export const PAGE_LANE_META: Record<
  PageLane,
  { label: string; scope: string; accent: string }
> = {
  command: { label: "Posture", scope: "Current · connected surfaces", accent: "var(--graph-server)" },
  "ai-estate": { label: "AI inventory", scope: "Agents · fleet · manifests", accent: "var(--status-success)" },
  "cloud-data": { label: "Connect", scope: "Sources · connect & scan", accent: "var(--graph-tool)" },
  runtime: { label: "Runtime", scope: "Live · Enforced", accent: "var(--graph-credential)" },
  governance: { label: "Governance", scope: "Policy & evidence", accent: "var(--status-success)" },
  reference: { label: "Reference", scope: "Catalog · Not yours", accent: "var(--graph-package)" },
  operations: { label: "Operations", scope: "AI usage · Jobs", accent: "var(--status-warn)" },
};

const PATH_TO_LANE: Record<string, PageLane> = {
  "/": "command",
  "/findings": "command",
  "/advisories": "command",
  "/security-graph": "command",
  "/remediation": "command",
  "/graph": "command",
  "/mesh": "command",
  "/context": "command",
  "/agents": "ai-estate",
  "/skills": "ai-estate",
  "/manifest": "ai-estate",
  "/fleet": "ai-estate",
  "/connections": "cloud-data",
  "/sources": "cloud-data",
  "/scan": "cloud-data",
  "/runtime": "runtime",
  "/traces": "runtime",
  "/identity": "runtime",
  "/compliance": "governance",
  "/blueprints": "governance",
  "/governance": "governance",
  "/drift": "governance",
  "/audit": "governance",
  "/registry": "reference",
  "/cost": "operations",
  "/jobs": "operations",
  "/activity": "operations",
};

export function laneForPath(path: string): PageLane | null {
  if (PATH_TO_LANE[path]) {
    return PATH_TO_LANE[path]!;
  }
  const match = Object.keys(PATH_TO_LANE)
    .filter((prefix) => prefix !== "/")
    .sort((a, b) => b.length - a.length)
    .find((prefix) => path.startsWith(prefix));
  return match ? PATH_TO_LANE[match]! : null;
}
